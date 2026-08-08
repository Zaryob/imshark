// SCTP chunk bodies and parameters: see sctp_chunks.h.
#include "sctp_chunks.h"

#include <algorithm>
#include <cstring>

#include <network/byteorder.h>

#include "util.h"

using packet::Field;

namespace dissect::sctp {
    namespace {
        inline uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
        inline uint32_t rd32(const uint8_t *p) {
            return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
        }
        constexpr size_t kMaxTlvs = 256;   // parameters / causes / list entries shown per chunk

        std::string hexPreview(const uint8_t *p, size_t n, size_t max = 16) {
            static const char *digits = "0123456789abcdef";
            std::string out;
            for (size_t i = 0; i < n && i < max; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; }
            if (n > max) out += "...";
            return out;
        }

        std::string paramName(uint16_t type) {
            switch (type) {
                case 1: return "Heartbeat Info";
                case 5: return "IPv4 Address";
                case 6: return "IPv6 Address";
                case 7: return "State Cookie";
                case 8: return "Unrecognized Parameter";
                case 9: return "Cookie Preservative";
                case 11: return "Host Name Address";
                case 12: return "Supported Address Types";
                case 0x8000: return "ECN Capable";
                case 0x8002: return "Random";
                case 0x8003: return "Chunk List";
                case 0x8004: return "Requested HMAC Algorithm";
                case 0x8008: return "Supported Extensions";
                case 0xC000: return "Forward TSN Supported";
                case 0xC006: return "Adaptation Layer Indication";
                default: return "Parameter " + std::to_string(type);
            }
        }

        std::string causeName(uint16_t code) {
            switch (code) {
                case 1: return "Invalid Stream Identifier";
                case 2: return "Missing Mandatory Parameter";
                case 3: return "Stale Cookie";
                case 4: return "Out of Resource";
                case 5: return "Unresolvable Address";
                case 6: return "Unrecognized Chunk Type";
                case 7: return "Invalid Mandatory Parameter";
                case 8: return "Unrecognized Parameters";
                case 9: return "No User Data";
                case 10: return "Cookie Received While Shutting Down";
                case 11: return "Restart of an Association with New Addresses";
                case 12: return "User-Initiated Abort";
                case 13: return "Protocol Violation";
                default: return "Cause " + std::to_string(code);
            }
        }

        std::string hmacName(uint16_t id) {
            switch (id) {
                case 1: return "SHA-1";
                case 3: return "SHA-256";
                default: return "HMAC identifier " + std::to_string(id);
            }
        }

        std::string ipv6Text(const uint8_t *p) {
            static const char *digits = "0123456789abcdef";
            std::string out;
            for (int i = 0; i < 16; i += 2) {
                if (i) out += ':';
                bool started = false;
                for (int nib : {p[i] >> 4, p[i] & 15, p[i + 1] >> 4, p[i + 1] & 15}) {
                    if (nib || started) { out += digits[nib]; started = true; }
                }
                if (!started) out += '0';
            }
            return out;
        }

        std::string ipv4Text(const uint8_t *p) {
            return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." + std::to_string(p[2]) + "." + std::to_string(p[3]);
        }

        // Calls each(type, tlv, length, shownLength) for the TLVs of [p, p + shown): 16 bit type, 16 bit length (header
        // included), value padded to 4 bytes. Returns a problem text for a length below 4 or a TLV running past the end.
        template<typename F>
        const char *walkTlvs(const uint8_t *p, size_t shown, const char *what, F &&each) {
            size_t pos = 0;
            for (size_t n = 0; pos + 4 <= shown && n < kMaxTlvs; ++n) {
                const uint16_t type = rd16(p + pos), length = rd16(p + pos + 2);
                if (length < 4) return what;
                const size_t room = shown - pos;
                if (length > room) {
                    each(type, p + pos, static_cast<size_t>(length), room);
                    return what;
                }
                each(type, p + pos, static_cast<size_t>(length), static_cast<size_t>(length));
                pos += (static_cast<size_t>(length) + 3) & ~static_cast<size_t>(3);
            }
            return nullptr;
        }

        // A list of 1 byte or 2 byte items (chunk types, address types, HMAC identifiers)
        void addTypeList(Field &f, const uint8_t *v, size_t n, size_t width, size_t base, uint8_t kind) {
            for (size_t i = 0; i + width <= n && i / width < kMaxTlvs; i += width) {
                const unsigned value = width == 1 ? v[i] : rd16(v + i);
                std::string text;
                if (kind == 0) text = "Chunk Type: " + std::to_string(value) + " (" + chunkTypeName(static_cast<uint8_t>(value)) + ")";
                else if (kind == 1) text = "Address Type: " + std::to_string(value) + (value == 5 ? " (IPv4)" : value == 6 ? " (IPv6)" : value == 11 ? " (Host Name)" : "");
                else text = "HMAC Identifier: " + std::to_string(value) + " (" + hmacName(static_cast<uint16_t>(value)) + ")";
                f.add(text, base + i, width);
            }
        }

        // The value of one INIT / INIT ACK / HEARTBEAT parameter; `v` is the value (after the 4 byte header), `n` its shown length
        void paramValue(Field &pf, uint16_t type, const uint8_t *v, size_t n, size_t base) {
            switch (type) {
                case 1:
                    pf.add("Heartbeat Information (" + std::to_string(n) + " bytes): " + hexPreview(v, n), base, n);
                    break;
                case 5:
                    if (n >= 4) pf.add("IPv4 address: " + ipv4Text(v), base, 4);
                    break;
                case 6:
                    if (n >= 16) pf.add("IPv6 address: " + ipv6Text(v), base, 16);
                    break;
                case 7:
                    pf.add("State Cookie (" + std::to_string(n) + " bytes)", base, n);
                    break;
                case 8:
                    if (n >= 4) {
                        pf.add("Unrecognized parameter type: " + std::to_string(rd16(v)), base, 2);
                        pf.add("Unrecognized parameter length: " + std::to_string(rd16(v + 2)), base + 2, 2);
                    }
                    break;
                case 9:
                    if (n >= 4) pf.add("Suggested Cookie Life-Span Increment (msec): " + std::to_string(rd32(v)), base, 4);
                    break;
                case 11:
                    pf.add("Host name: " + printableText(v, n, 100), base, n);
                    break;
                case 12:
                    addTypeList(pf, v, n, 2, base, 1);
                    break;
                case 0x8002:
                    pf.add("Random number (" + std::to_string(n) + " bytes): " + hexPreview(v, n), base, n);
                    break;
                case 0x8003:
                    addTypeList(pf, v, n, 1, base, 0);
                    break;
                case 0x8004:
                    addTypeList(pf, v, n, 2, base, 2);
                    break;
                case 0x8008:
                    addTypeList(pf, v, n, 1, base, 0);
                    break;
                case 0xC006:
                    if (n >= 4) pf.add("Adaptation Code Point: " + std::to_string(rd32(v)), base, 4);
                    break;
                default:
                    if (n) pf.add("Value (" + std::to_string(n) + " bytes): " + hexPreview(v, n), base, n);
                    break;
            }
        }

        const char *walkParams(Field *tree, const uint8_t *p, size_t shown, size_t base, const char *what) {
            return walkTlvs(p, shown, what, [&](uint16_t type, const uint8_t *tlv, size_t length, size_t have) {
                if (!tree) return;
                const size_t off = base + static_cast<size_t>(tlv - p);
                Field &pf = tree->add("Parameter: " + paramName(type) + " (Type: " + std::to_string(type) + ", Length: " + std::to_string(length) + ")", off, have);
                pf.add("Parameter Type: " + std::to_string(type) + " (" + paramName(type) + ")", off, 2);
                pf.add("Parameter Length: " + std::to_string(length), off + 2, 2);
                paramValue(pf, type, tlv + 4, have - 4, off + 4);
            });
        }

        void causeValue(Field &cf, uint16_t code, const uint8_t *v, size_t n, size_t base) {
            switch (code) {
                case 1:
                    if (n >= 2) cf.add("Stream Identifier: " + std::to_string(rd16(v)), base, 2);
                    break;
                case 2:
                    if (n >= 4) {
                        const uint32_t count = rd32(v);
                        cf.add("Number of missing parameters: " + std::to_string(count), base, 4);
                        for (size_t i = 0; i < count && 4 + 2 * i + 2 <= n && i < kMaxTlvs; ++i)
                            cf.add("Missing parameter type: " + std::to_string(rd16(v + 4 + 2 * i)) + " (" + paramName(rd16(v + 4 + 2 * i)) + ")", base + 4 + 2 * i, 2);
                    }
                    break;
                case 3:
                    if (n >= 4) cf.add("Measure of Staleness (usec): " + std::to_string(rd32(v)), base, 4);
                    break;
                case 5:
                case 8:
                case 11: {
                    // a parameter (5), several parameters (8), the new addresses as parameters (11)
                    walkTlvs(v, n, "", [&](uint16_t type, const uint8_t *tlv, size_t length, size_t have) {
                        const size_t off = base + static_cast<size_t>(tlv - v);
                        Field &pf = cf.add("Parameter: " + paramName(type) + " (Type: " + std::to_string(type) + ", Length: " + std::to_string(length) + ")", off, have);
                        paramValue(pf, type, tlv + 4, have - 4, off + 4);
                    });
                    break;
                }
                case 6:
                    if (n >= 4) {
                        cf.add("Unrecognized chunk type: " + std::to_string(v[0]) + " (" + chunkTypeName(v[0]) + ")", base, 1);
                        cf.add("Unrecognized chunk length: " + std::to_string(rd16(v + 2)), base + 2, 2);
                    }
                    break;
                case 9:
                    if (n >= 4) cf.add("TSN value: " + std::to_string(rd32(v)), base, 4);
                    break;
                case 12:
                case 13:
                    if (n) cf.add(std::string(code == 12 ? "Reason: " : "Information: ") + printableText(v, n, 200), base, n);
                    break;
                default:
                    if (n) cf.add("Value (" + std::to_string(n) + " bytes): " + hexPreview(v, n), base, n);
                    break;
            }
        }

        const char *walkCauses(Field *tree, const uint8_t *p, size_t shown, size_t base) {
            return walkTlvs(p, shown, "Invalid SCTP error cause length", [&](uint16_t code, const uint8_t *tlv, size_t length, size_t have) {
                if (!tree) return;
                const size_t off = base + static_cast<size_t>(tlv - p);
                Field &cf = tree->add("Error cause: " + causeName(code) + " (Code: " + std::to_string(code) + ", Length: " + std::to_string(length) + ")", off, have);
                cf.add("Cause Code: " + std::to_string(code) + " (" + causeName(code) + ")", off, 2);
                cf.add("Cause Length: " + std::to_string(length), off + 2, 2);
                causeValue(cf, code, tlv + 4, have - 4, off + 4);
            });
        }
    } // namespace

    std::string chunkTypeName(uint8_t type) {
        switch (type) {
            case 0: return "DATA";
            case 1: return "INIT";
            case 2: return "INIT_ACK";
            case 3: return "SACK";
            case 4: return "HEARTBEAT";
            case 5: return "HEARTBEAT_ACK";
            case 6: return "ABORT";
            case 7: return "SHUTDOWN";
            case 8: return "SHUTDOWN_ACK";
            case 9: return "ERROR";
            case 10: return "COOKIE_ECHO";
            case 11: return "COOKIE_ACK";
            case 12: return "ECNE";
            case 13: return "CWR";
            case 14: return "SHUTDOWN_COMPLETE";
            case 15: return "AUTH";
            case 64: return "I_DATA";
            case 128: return "ASCONF_ACK";
            case 130: return "RE_CONFIG";
            case 132: return "PAD";
            case 192: return "FORWARD_TSN";
            case 193: return "ASCONF";
            case 194: return "I_FORWARD_TSN";
            default: return "Chunk " + std::to_string(type);
        }
    }

    std::string ppidName(uint32_t ppid) {
        switch (ppid) {
            case 0: return "Reserved";
            case 1: return "IUA";
            case 2: return "M2UA";
            case 3: return "M3UA";
            case 4: return "SUA";
            case 5: return "M2PA";
            case 6: return "V5UA";
            case 7: return "H.248";
            case 8: return "BICC/Q.2150.3";
            case 9: return "TALI";
            case 10: return "DUA";
            case 11: return "ASAP";
            case 12: return "ENRP";
            case 13: return "H.323";
            case 14: return "Q.IPC/Q.2150.3";
            case 15: return "SIMCO";
            case 16: return "DDP Segment Chunk";
            case 17: return "DDP Stream Session Control";
            case 18: return "S1AP";
            case 19: return "RUA";
            case 20: return "HNBAP";
            case 25: return "NBAP";
            case 27: return "X2AP";
            case 38: return "ECHO";
            case 39: return "DISCARD";
            case 40: return "DAYTIME";
            case 41: return "CHARGEN";
            case 45: return "SSH over SCTP";
            case 46: return "Diameter";
            case 47: return "Diameter over DTLS";
            case 50: return "WebRTC DCEP";
            case 51: return "WebRTC String";
            case 52: return "WebRTC Binary Partial";
            case 53: return "WebRTC Binary";
            case 54: return "WebRTC String Partial";
            case 56: return "WebRTC String Empty";
            case 57: return "WebRTC Binary Empty";
            case 60: return "NGAP";
            case 61: return "XnAP";
            case 62: return "F1AP";
            case 63: return "E1AP";
            default: return "";
        }
    }

    bool readDataHeader(const uint8_t *chunk, size_t shown, size_t stated, DataHeader &out, const char **problem) {
        const bool idata = chunk[0] == kIData;
        const size_t header = idata ? 20 : 16;
        out = DataHeader{};
        if (stated < header) {
            if (problem && !*problem) *problem = idata ? "SCTP I-DATA chunk shorter than its header" : "SCTP DATA chunk shorter than its header";
            return false;
        }
        if (shown < header) return false;
        out.idata = idata;
        out.end = chunk[1] & 0x01;
        out.begin = chunk[1] & 0x02;
        out.unordered = chunk[1] & 0x04;
        out.immediate = chunk[1] & 0x08;
        out.tsn = rd32(chunk + 4);
        out.stream = rd16(chunk + 8);
        out.headerLength = header;
        if (idata) {
            out.ssn = rd32(chunk + 12);
            if (out.begin) { out.hasPpid = true; out.ppid = rd32(chunk + 16); }
            else out.fsn = rd32(chunk + 16);
        } else {
            out.ssn = rd16(chunk + 10);
            out.hasPpid = true;
            out.ppid = rd32(chunk + 12);
        }
        return true;
    }

    void addDataHeaderFields(Field &cf, const DataHeader &h, size_t o, size_t stated) {
        std::string flags = std::string(h.immediate ? "I" : "-") + (h.unordered ? "U" : "-") + (h.begin ? "B" : "-") + (h.end ? "E" : "-");
        Field &fl = cf.add("Flags: " + hexString(static_cast<uint32_t>((h.immediate << 3) | (h.unordered << 2) | (h.begin << 1) | h.end), 2) + " (" + flags + ")", o + 1, 1);
        fl.add(std::string("Immediate: ") + (h.immediate ? "set" : "not set"), o + 1, 1);
        fl.add(std::string("Unordered: ") + (h.unordered ? "set" : "not set"), o + 1, 1);
        fl.add(std::string("Beginning of a user message: ") + (h.begin ? "set" : "not set"), o + 1, 1);
        fl.add(std::string("End of a user message: ") + (h.end ? "set" : "not set"), o + 1, 1);
        cf.add("Length: " + std::to_string(stated), o + 2, 2);
        cf.add("TSN: " + std::to_string(h.tsn), o + 4, 4);
        cf.add("Stream Identifier: " + std::to_string(h.stream), o + 8, 2);
        if (h.idata) {
            cf.add("Reserved: 0x" + std::string("0000"), o + 10, 2);
            cf.add("Message Identifier: " + std::to_string(h.ssn), o + 12, 4);
            if (h.hasPpid) {
                const std::string name = ppidName(h.ppid);
                cf.add("Payload Protocol Identifier: " + std::to_string(h.ppid) + (name.empty() ? "" : " (" + name + ")"), o + 16, 4);
            } else {
                cf.add("Fragment Sequence Number: " + std::to_string(h.fsn), o + 16, 4);
            }
        } else {
            cf.add("Stream Sequence Number: " + std::to_string(h.ssn), o + 10, 2);
            const std::string name = ppidName(h.ppid);
            cf.add("Payload Protocol Identifier: " + std::to_string(h.ppid) + (name.empty() ? "" : " (" + name + ")"), o + 12, 4);
        }
    }

    const char *decodeBody(Field *tree, uint8_t type, uint8_t flags, const uint8_t *c, size_t shown, size_t stated, size_t o) {
        // a fixed part of `n` bytes (chunk header included): too short by its own length is a problem, cut by the capture is not
        auto fixed = [&](size_t n, const char *text, const char **problem) {
            if (stated < n) { *problem = text; return false; }
            return shown >= n;
        };
        const char *problem = nullptr;
        if (shown < 4 || stated < 4) return problem;   // not a chunk (the caller reports the length)
        switch (type) {
            case kInit:
            case kInitAck: {
                if (!fixed(20, "SCTP INIT chunk shorter than its fixed part", &problem)) break;
                if (tree) {
                    tree->add("Initiate Tag: " + hexString(rd32(c + 4), 8), o + 4, 4);
                    tree->add("Advertised Receiver Window Credit (a_rwnd): " + std::to_string(rd32(c + 8)), o + 8, 4);
                    tree->add("Number of Outbound Streams: " + std::to_string(rd16(c + 12)), o + 12, 2);
                    tree->add("Number of Inbound Streams: " + std::to_string(rd16(c + 14)), o + 14, 2);
                    tree->add("Initial TSN: " + std::to_string(rd32(c + 16)), o + 16, 4);
                }
                problem = walkParams(tree, c + 20, shown - 20, o + 20, "Invalid SCTP parameter length");
                break;
            }
            case kSack: {
                if (!fixed(16, "SCTP SACK chunk shorter than its fixed part", &problem)) break;
                const uint32_t cum = rd32(c + 4);
                const size_t gaps = rd16(c + 12), dups = rd16(c + 14);
                if (tree) {
                    tree->add("Cumulative TSN Ack: " + std::to_string(cum), o + 4, 4);
                    tree->add("Advertised Receiver Window Credit (a_rwnd): " + std::to_string(rd32(c + 8)), o + 8, 4);
                    tree->add("Number of Gap Ack Blocks: " + std::to_string(gaps), o + 12, 2);
                    tree->add("Number of Duplicate TSNs: " + std::to_string(dups), o + 14, 2);
                }
                if (16 + 4 * gaps + 4 * dups > stated) problem = "SCTP SACK block counts exceed the chunk length";
                for (size_t i = 0; i < gaps && 16 + 4 * i + 4 <= shown; ++i) {
                    if (!tree) break;
                    const uint16_t start = rd16(c + 16 + 4 * i), end = rd16(c + 18 + 4 * i);
                    tree->add("Gap Ack Block #" + std::to_string(i + 1) + ": start offset " + std::to_string(start) + ", end offset " + std::to_string(end) +
                              " (TSN " + std::to_string(static_cast<uint32_t>(cum + start)) + " - " + std::to_string(static_cast<uint32_t>(cum + end)) + ")", o + 16 + 4 * i, 4);
                }
                for (size_t i = 0; i < dups && 16 + 4 * gaps + 4 * i + 4 <= shown; ++i) {
                    if (!tree) break;
                    tree->add("Duplicate TSN: " + std::to_string(rd32(c + 16 + 4 * gaps + 4 * i)), o + 16 + 4 * gaps + 4 * i, 4);
                }
                break;
            }
            case kHeartbeat:
            case kHeartbeatAck:
                problem = walkParams(tree, c + 4, shown - 4, o + 4, "Invalid SCTP parameter length");
                break;
            case kAbort:
            case kError:
                if (tree && type == kAbort) tree->add(std::string("T bit: ") + ((flags & 1) ? "set (the sender had no association; verification tag reflected)" : "not set"), o + 1, 1);
                problem = walkCauses(tree, c + 4, shown - 4, o + 4);
                break;
            case kShutdown:
                if (!fixed(8, "SCTP SHUTDOWN chunk shorter than its fixed part", &problem)) break;
                if (tree) tree->add("Cumulative TSN Ack: " + std::to_string(rd32(c + 4)), o + 4, 4);
                break;
            case kShutdownComplete:
                if (tree) tree->add(std::string("T bit: ") + ((flags & 1) ? "set (the sender had no association; verification tag reflected)" : "not set"), o + 1, 1);
                break;
            case kCookieEcho:
                if (tree && shown > 4) tree->add("Cookie (" + std::to_string(shown - 4) + " bytes)", o + 4, shown - 4);
                break;
            case kEcne:
            case kCwr:
                if (!fixed(8, type == kEcne ? "SCTP ECNE chunk shorter than its fixed part" : "SCTP CWR chunk shorter than its fixed part", &problem)) break;
                if (tree) tree->add("Lowest TSN: " + std::to_string(rd32(c + 4)), o + 4, 4);
                break;
            case kForwardTsn: {
                if (!fixed(8, "SCTP FORWARD_TSN chunk shorter than its fixed part", &problem)) break;
                if (tree) tree->add("New Cumulative TSN: " + std::to_string(rd32(c + 4)), o + 4, 4);
                if ((stated - 8) % 4) problem = "SCTP FORWARD_TSN stream list is not a multiple of 4 bytes";
                for (size_t i = 0; tree && 8 + 4 * i + 4 <= shown && i < kMaxTlvs; ++i)
                    tree->add("Stream: " + std::to_string(rd16(c + 8 + 4 * i)) + ", Stream Sequence Number: " + std::to_string(rd16(c + 10 + 4 * i)), o + 8 + 4 * i, 4);
                break;
            }
            case kIForwardTsn: {
                if (!fixed(8, "SCTP I_FORWARD_TSN chunk shorter than its fixed part", &problem)) break;
                if (tree) tree->add("New Cumulative TSN: " + std::to_string(rd32(c + 4)), o + 4, 4);
                if ((stated - 8) % 8) problem = "SCTP I_FORWARD_TSN stream list is not a multiple of 8 bytes";
                for (size_t i = 0; tree && 8 + 8 * i + 8 <= shown && i < kMaxTlvs; ++i)
                    tree->add("Stream: " + std::to_string(rd16(c + 8 + 8 * i)) + std::string(", ") + ((rd16(c + 10 + 8 * i) & 1) ? "unordered" : "ordered") +
                              ", Message Identifier: " + std::to_string(rd32(c + 12 + 8 * i)), o + 8 + 8 * i, 8);
                break;
            }
            default:
                break;   // SHUTDOWN_ACK, COOKIE_ACK and the chunks whose body is not decoded (AUTH, ASCONF, RE_CONFIG, PAD)
        }
        return problem;
    }
} // namespace dissect::sctp

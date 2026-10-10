#include "export.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>

#include <core.h>

namespace exporter {
    namespace {
        void put16(std::string &out, uint16_t v) { for (int i = 0; i < 2; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }
        void put32(std::string &out, uint32_t v) { for (int i = 0; i < 4; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }

        // microseconds since the epoch of a packet; never negative
        uint64_t micros(const packet::PacketInfo &p, double startEpoch) {
            const double t = (startEpoch + p.time) * 1e6;
            return t <= 0 ? 0 : static_cast<uint64_t>(std::llround(t));
        }

        std::string number(double v, int digits = 6) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.*f", digits, v);
            return buf;
        }

        // nanoseconds since the epoch of a packet; never negative. Integer arithmetic from the exact capture start when
        // known (p.time is a double relative to the first packet: ample for nanoseconds over a capture of weeks).
        uint64_t nanos(const packet::PacketInfo &p, double startEpoch, const core::CaptureInfo *info) {
            if (info && info->hasStart) {
                const long long rel = std::llround(p.time * 1e9);
                const long long t = static_cast<long long>(info->startSeconds) * 1000000000LL + info->startNanos + rel;
                return t <= 0 ? 0 : static_cast<uint64_t>(t);
            }
            const double t = (startEpoch + p.time) * 1e9;
            return t <= 0 ? 0 : static_cast<uint64_t>(std::llround(t));
        }

        // "seconds.fraction" of an instant given in nanoseconds, with 6 or 9 decimals (truncated)
        std::string epochText(uint64_t ns, int digits) {
            char buf[64];
            const unsigned long long sec = ns / 1000000000ull, frac = ns % 1000000000ull;
            if (digits >= 9) std::snprintf(buf, sizeof(buf), "%llu.%09llu", sec, frac);
            else std::snprintf(buf, sizeof(buf), "%llu.%06llu", sec, frac / 1000);
            return buf;
        }
    } // namespace

    const char *formatName(Format f) {
        switch (f) {
            case Format::Pcap: return "pcap";
            case Format::Pcapng: return "pcapng";
            case Format::Csv: return "CSV";
            case Format::Json: return "JSON";
        }
        return "";
    }

    const char *formatExtension(Format f) {
        switch (f) {
            case Format::Pcap: return ".pcap";
            case Format::Pcapng: return ".pcapng";
            case Format::Csv: return ".csv";
            case Format::Json: return ".json";
        }
        return "";
    }

    bool isCaptureFormat(Format f) { return f == Format::Pcap || f == Format::Pcapng; }

    std::string csvField(const std::string &text) {
        std::string out = "\"";
        for (char c: text) {
            if (c == '"') out += "\"\"";
            else out += c;
        }
        return out + "\"";
    }

    std::string jsonString(const std::string &text) {
        std::string out = "\"";
        for (unsigned char c: text) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        return out + "\"";
    }

    void writeCsv(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices,
                  int fractionDigits) {
        out << "\"No.\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"\n";
        for (uint32_t i: indices) {
            if (i >= packets.size()) continue;
            const auto &p = packets[i];
            out << csvField(std::to_string(p.number)) << ',' << csvField(number(p.time, fractionDigits)) << ',' << csvField(p.source) << ',' << csvField(p.destination)
                << ',' << csvField(p.protocol) << ',' << csvField(std::to_string(p.frame_length)) << ',' << csvField(p.info) << '\n';
        }
    }

    void writeJson(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices,
                   double captureStartEpoch, int fractionDigits, const core::CaptureInfo *info) {
        out << "[";
        bool first = true;
        for (uint32_t i: indices) {
            if (i >= packets.size()) continue;
            const auto &p = packets[i];
            out << (first ? "\n  " : ",\n  ") << "{\"number\": " << p.number << ", \"time\": " << number(p.time, fractionDigits)
                << ", \"time_epoch\": "
                << (info && info->hasStart ? epochText(nanos(p, captureStartEpoch, info), fractionDigits) : number(captureStartEpoch + p.time, fractionDigits)) << ", \"source\": " << jsonString(p.source)
                << ", \"destination\": " << jsonString(p.destination) << ", \"protocol\": " << jsonString(p.protocol)
                << ", \"length\": " << p.frame_length << ", \"info\": " << jsonString(p.info) << "}";
            first = false;
        }
        out << (first ? "]\n" : "\n]\n");
    }

    bool exportPackets(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                       const std::vector<uint32_t> &indices, double captureStartEpoch, Format format,
                       const std::string &outPath, std::string &error, core::ScanControl *control,
                       const std::vector<core::DecryptionSecrets> *secrets, const core::CaptureInfo *info) {
        error.clear();
        const bool ns = info && info->nanosecondTimestamps();
        // Reject aliases too: opening a symlink or hard link would truncate the capture before it can be read.
        std::error_code pathError;
        if (std::filesystem::equivalent(core::pathFromUtf8(capturePath), core::pathFromUtf8(outPath), pathError)) {
            error = "The export destination is the open capture file; choose a different file";
            return false;
        }

        // Validate before opening the output so a rejected classic pcap export preserves an existing file.
        std::vector<uint32_t> linkTypes;
        uint32_t maxCaptured = 0;
        if (isCaptureFormat(format)) {
            for (uint32_t i: indices) {
                if (i >= packets.size()) continue;
                if (std::find(linkTypes.begin(), linkTypes.end(), packets[i].link_type) == linkTypes.end()) linkTypes.push_back(packets[i].link_type);
                maxCaptured = std::max(maxCaptured, packets[i].captured_length);
            }
            if (linkTypes.empty()) linkTypes.push_back(1);
            if (format == Format::Pcap && linkTypes.size() > 1) {
                error = "The packets use different link types; save them as pcapng instead";
                return false;
            }
        }

        std::ofstream out(core::pathFromUtf8(outPath), std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "Cannot write to " + outPath;
            return false;
        }

        if (!isCaptureFormat(format)) {
            const int digits = ns ? 9 : 6;
            if (format == Format::Csv) writeCsv(out, packets, indices, digits);
            else writeJson(out, packets, indices, captureStartEpoch, digits, info);
            out.flush();
            if (!out) { error = "Writing to " + outPath + " failed"; return false; }
            return true;
        }

        const uint32_t snaplen = std::max<uint32_t>(maxCaptured, 262144);

        std::string head;
        if (format == Format::Pcap) {
            put32(head, ns ? 0xa1b23c4d : 0xa1b2c3d4);
            put16(head, 2);
            put16(head, 4);
            put32(head, 0);
            put32(head, 0);
            put32(head, snaplen);
            put32(head, linkTypes[0]);
        } else {
            // Section Header Block with the shb_userappl option
            const std::string app = "ImShark";
            std::string shbBody;
            put32(shbBody, 0x1A2B3C4D);
            put16(shbBody, 1);
            put16(shbBody, 0);
            put32(shbBody, 0xffffffffu); put32(shbBody, 0xffffffffu); // section length unknown
            put16(shbBody, 4); put16(shbBody, static_cast<uint16_t>(app.size()));
            shbBody += app;
            shbBody.append((4 - app.size() % 4) % 4, '\0');
            put16(shbBody, 0); put16(shbBody, 0);                      // opt_endofopt
            put32(head, 0x0A0D0D0A); put32(head, static_cast<uint32_t>(shbBody.size() + 12)); head += shbBody; put32(head, static_cast<uint32_t>(shbBody.size() + 12));
            for (uint32_t lt: linkTypes) {
                std::string idb;
                put16(idb, static_cast<uint16_t>(lt)); put16(idb, 0); put32(idb, 0); // linktype, reserved, snaplen (0 = no limit)
                if (ns) {
                    put16(idb, 9); put16(idb, 1);                                    // if_tsresol: 10^-9 s, padded to 4 bytes
                    idb += static_cast<char>(9);
                    idb.append(3, '\0');
                    put16(idb, 0); put16(idb, 0);                                    // opt_endofopt
                }
                put32(head, 1); put32(head, static_cast<uint32_t>(idb.size() + 12)); head += idb; put32(head, static_cast<uint32_t>(idb.size() + 12));
            }
            // Decryption Secrets Blocks: secrets type, secrets length, the secrets padded to 4 bytes
            if (secrets) {
                for (const auto &dsb: *secrets) {
                    std::string body;
                    put32(body, dsb.type);
                    put32(body, static_cast<uint32_t>(dsb.data.size()));
                    body += dsb.data;
                    body.append((4 - dsb.data.size() % 4) % 4, '\0');
                    put32(head, 0x0A); put32(head, static_cast<uint32_t>(body.size() + 12)); head += body; put32(head, static_cast<uint32_t>(body.size() + 12));
                }
            }
        }
        out.write(head.data(), static_cast<std::streamsize>(head.size()));

        std::string rec;
        const bool completed = core::scanPackets(capturePath, packets, indices, [&](const packet::PacketInfo &p, const std::vector<char> &frame) {
            rec.clear();
            // ticks since the epoch in the file's resolution
            const uint64_t us = ns ? nanos(p, captureStartEpoch, info)
                                   : (info && info->hasStart ? (nanos(p, captureStartEpoch, info) + 500) / 1000 : micros(p, captureStartEpoch));
            const uint64_t perSecond = ns ? 1000000000ull : 1000000ull;
            if (format == Format::Pcap) {
                put32(rec, static_cast<uint32_t>(us / perSecond));
                put32(rec, static_cast<uint32_t>(us % perSecond));
                put32(rec, static_cast<uint32_t>(frame.size()));
                put32(rec, std::max<uint32_t>(p.frame_length, static_cast<uint32_t>(frame.size())));
                rec.append(frame.data(), frame.size());
            } else {
                const uint32_t iface = static_cast<uint32_t>(std::find(linkTypes.begin(), linkTypes.end(), p.link_type) - linkTypes.begin());
                const size_t padded = (frame.size() + 3) & ~static_cast<size_t>(3);
                std::string body;
                put32(body, iface);
                put32(body, static_cast<uint32_t>(us >> 32));
                put32(body, static_cast<uint32_t>(us & 0xffffffffu));
                put32(body, static_cast<uint32_t>(frame.size()));
                put32(body, std::max<uint32_t>(p.frame_length, static_cast<uint32_t>(frame.size())));
                body.append(frame.data(), frame.size());
                body.append(padded - frame.size(), '\0');
                put32(rec, 6); put32(rec, static_cast<uint32_t>(body.size() + 12)); rec += body; put32(rec, static_cast<uint32_t>(body.size() + 12));
            }
            out.write(rec.data(), static_cast<std::streamsize>(rec.size()));
            return static_cast<bool>(out);
        }, control);

        out.flush();
        if (!completed) {                       // cancelled, or the capture could not be read
            if (!(control && control->cancelRequested)) error = "The capture file could not be read";
            return false;
        }
        if (!out) { error = "Writing to " + outPath + " failed"; return false; }
        return true;
    }
} // namespace exporter

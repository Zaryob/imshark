// SCTP (Stream Control Transmission Protocol, RFC 9260 / 4960) dissector:
// Common header + CRC-32C verification + the chunks with their bodies and parameters (sctp_chunks.cpp).
#include "sctp.h"

#include <algorithm>
#include <string>
#include <vector>

#include "checksum.h"
#include "sctp_chunks.h"
#include "util.h"
#include <network/byteorder.h>

using packet::Field;

namespace {
    using namespace dissect;

    std::string sctpChunkTypeName(uint8_t type) { return sctp::chunkTypeName(type); }
} // namespace

void dissect::dissectSctp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "SCTP";

    if (length < 12) {
        ctx.markMalformed("SCTP common header truncated");
        pack.info = "SCTP [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    auto readU16 = [](const uint8_t *p) -> uint16_t {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    };
    auto readU32 = [](const uint8_t *p) -> uint32_t {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8)  |
                static_cast<uint32_t>(p[3]);
    };

    const uint16_t srcPort = readU16(bytes);
    const uint16_t dstPort = readU16(bytes + 2);
    const uint32_t vtag = readU32(bytes + 4);

    pack.src_port = srcPort;
    pack.dst_port = dstPort;
    pack.length = static_cast<uint32_t>(length);
    pack.tcp_pdu_start = vtag; // Store vtag in summary

    // Verify CRC-32C
    uint32_t storedCrc = 0, calcCrc = 0;
    bool csumGood = checkSctpCrc32c(data, length, &storedCrc, &calcCrc);
    pack.checksum_state = static_cast<uint8_t>((pack.checksum_state & ~0x0c) |
                          ((csumGood ? kChecksumGood : kChecksumBad) << 2));

    // Parse chunks
    size_t offset = 12;
    std::string chunkSummary;
    uint8_t firstChunkType = 0xFF;

    struct ChunkInfo {
        uint8_t type;
        uint8_t flags;
        uint16_t length;   // as the chunk header states it
        size_t shown;      // what lies inside the packet: min(length, bytes left)
        size_t off;
        ChunkInfo(uint8_t t, uint8_t f, uint16_t l, size_t s, size_t o) : type(t), flags(f), length(l), shown(s), off(o) {}
        bool hasData = false;                      // DATA / I-DATA whose header is all there
        sctp::DataHeader dh;
        size_t userLength = 0;                     // user data bytes inside the packet
        bool fragment = false;                     // carries only part of a user message
        const SctpFragmentRef *ref = nullptr;      // what the load pass found out about the fragment
        const SctpMessage *message = nullptr;      // set when this chunk's fragment completed its message
        bool lost = false;                         // a fragment the session table did not keep
    };
    std::vector<ChunkInfo> chunks;
    bool chunkBeyondPacket = false;
    const char *malformed = nullptr;

    // reassembly (rule 4): the load pass hands the fragments to the session table, Replay only reads what it decided
    const bool loadPass = ctx.mode != ParseMode::Replay && ctx.sessions && !ctx.sessions->isFrozen();
    const uint32_t number = static_cast<uint32_t>(pack.number);
    std::vector<uint32_t> completions;             // other packets that completed messages this packet has fragments of

    while (offset + 4 <= length) {
        uint8_t ctype = bytes[offset];
        uint8_t cflags = bytes[offset + 1];
        uint16_t clen = readU16(bytes + offset + 2);

        if (firstChunkType == 0xFF) firstChunkType = ctype;

        const size_t room = length - offset;
        chunks.emplace_back(ctype, cflags, clen, clen < room ? clen : room, offset);
        ChunkInfo &ci = chunks.back();

        if (!chunkSummary.empty()) chunkSummary += ", ";
        chunkSummary += sctpChunkTypeName(ctype);

        if (clen < 4) {
            malformed = "Invalid SCTP chunk length (< 4)";
            break;
        }
        // the body of the chunk (what lies inside the packet); a problem with it is reported after the framing ones
        const char *bodyProblem = nullptr;
        if (ctype == sctp::kData || ctype == sctp::kIData) {
            ci.hasData = sctp::readDataHeader(bytes + offset, ci.shown, clen, ci.dh, &bodyProblem);
        } else {
            bodyProblem = sctp::decodeBody(nullptr, ctype, cflags, bytes + offset, ci.shown, clen, 0);
        }
        if (clen > room) {
            chunkBeyondPacket = true;
            malformed = "SCTP chunk length extends beyond the packet";
            ci.hasData = false;     // a cut chunk is neither counted nor reassembled
            break;
        }
        if (bodyProblem && !malformed) malformed = bodyProblem;

        if (ci.hasData) {
            const sctp::DataHeader &dh = ci.dh;
            ci.userLength = clen - dh.headerLength;
            ci.fragment = !(dh.begin && dh.end);
            if (ctx.sessions && offset <= 0xFFFF) {
                const auto position = static_cast<uint16_t>(offset);
                if (loadPass) {
                    ctx.sessions->noteSctpData(pack.source, srcPort, pack.destination, dstPort, dh.stream, ci.userLength, dh.end, number, position);
                    if (ci.fragment) {
                        SctpFragment f;
                        f.packet = number;
                        f.position = position;
                        f.idata = dh.idata;
                        f.begin = dh.begin;
                        f.end = dh.end;
                        f.unordered = dh.unordered;
                        f.stream = dh.stream;
                        f.ssn = dh.ssn;
                        f.sequence = dh.sequence();
                        f.ppid = dh.ppid;
                        f.data = data + offset + dh.headerLength;
                        f.size = ci.userLength;
                        f.time = pack.time;
                        std::vector<uint32_t> earlier;
                        ctx.sessions->addSctpFragment(pack.source, srcPort, pack.destination, dstPort, f, earlier);
                        if (ctx.completedDatagrams) {
                            // one earlier packet may hold fragments of several messages this packet completes: tell it once
                            for (uint32_t e: earlier) {
                                const std::pair<uint32_t, uint32_t> pair{e, number};
                                auto &done = *ctx.completedDatagrams;
                                if (std::find(done.begin(), done.end(), pair) == done.end()) done.push_back(pair);
                            }
                        }
                    }
                }
                if (ci.fragment) {
                    ci.ref = ctx.sessions->sctpFragment(number, position);
                    if (ci.ref) {
                        if (ci.ref->flags & SctpFragmentRef::kCompletesHere) ci.message = ctx.sessions->sctpMessage(ci.ref->message);
                        else if (ci.ref->completedIn && ci.ref->completedIn != number &&
                                 std::find(completions.begin(), completions.end(), ci.ref->completedIn) == completions.end())
                            completions.push_back(ci.ref->completedIn);
                    } else if (ctx.sessions->isTableStateLost("sctp")) {
                        ci.lost = true;
                    }
                }
            }
        }

        // Advance with 4-byte padding per RFC 4960 section 3.2
        offset += (static_cast<size_t>(clen) + 3) & ~static_cast<size_t>(3);
    }
    // a chunk cut off by the end of the capture: the CRC covers bytes that are not there
    if (chunkBeyondPacket) pack.checksum_state = static_cast<uint8_t>((pack.checksum_state & ~0x0c) | (kChecksumUnverified << 2));

    // facts for the display filter: the first DATA / I-DATA chunk (app_flags: 1 data, 2 I-DATA, 4 fragment, 8 completes a message
    // here, 16 unordered, 32 retransmission)
    pack.app_type = firstChunkType;
    pack.app_flags = 0;
    pack.app_code = 0;
    pack.tcp_pdu_len = 0;
    pack.app_stream = 0;
    pack.app_text2.clear();
    for (const auto &ci: chunks) {
        if (!ci.hasData) continue;
        pack.app_flags = static_cast<uint16_t>(1 | (ci.dh.idata ? 2 : 0) | (ci.fragment ? 4 : 0) | (ci.message ? 8 : 0) | (ci.dh.unordered ? 16 : 0) |
                                               ((ci.ref && (ci.ref->flags & SctpFragmentRef::kRetransmission)) ? 32 : 0));
        pack.app_code = ci.dh.stream;
        pack.tcp_pdu_len = ci.dh.tsn;
        pack.app_stream = ci.message ? ci.message->ppid : ci.dh.ppid;
        pack.app_text2 = std::to_string(ci.dh.ssn);
        break;
    }

    pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) + " [" +
                (chunkSummary.empty() ? "No chunks" : chunkSummary) + "]";
    {
        bool retransmission = false, conflict = false, rejected = false, lost = false;
        for (const auto &ci: chunks) {
            if (ci.message) pack.info += " [Reassembled SCTP message: " + std::to_string(ci.message->data.size()) + " bytes, stream " + std::to_string(ci.message->stream) + "]";
            if (ci.ref) {
                retransmission = retransmission || (ci.ref->flags & SctpFragmentRef::kRetransmission);
                conflict = conflict || (ci.ref->flags & SctpFragmentRef::kConflict);
                rejected = rejected || (ci.ref->flags & SctpFragmentRef::kRejected);
            }
            lost = lost || ci.lost;
        }
        if (retransmission) pack.info += " [Retransmission]";
        if (conflict) pack.info += " [Conflicting fragment]";
        if (rejected) pack.info += " [Fragment not reassembled]";
        if (lost) pack.info += " [SCTP reassembly state lost]";
    }
    if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it
    std::sort(completions.begin(), completions.end());
    for (uint32_t n: completions) pack.info += " [Reassembled in #" + std::to_string(n) + "]";

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        // RFC 6951: the SCTP packet is the payload of a UDP datagram; the ports and the CRC-32C are the SCTP ones
        const bool overUdp = pack.ip_protocol == 17;
        Field &l = ctx.addLayer("Stream Control Transmission Protocol, Src Port: " + std::to_string(srcPort) +
                                ", Dst Port: " + std::to_string(dstPort) + (overUdp ? " (UDP encapsulation)" : ""), o, length);

        l.add("Source Port: " + std::to_string(srcPort), o, 2);
        l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
        l.add("Verification Tag: " + hexString(vtag, 8), o + 4, 4);

        const uint8_t csumState = transportChecksumState(pack);
        Field &csumField = l.add("Checksum: " + hexString(storedCrc, 8) +
                                 (csumState == kChecksumUnverified ? " [Unverified: chunk cut off]" : csumGood ? " [Correct CRC-32C]" : " [Incorrect CRC-32C]"), o + 8, 4);
        csumField.add(std::string("[Checksum Status: ") + checksumStateText(csumState) + "]", o + 8, 4);
        if (csumState == kChecksumBad) {
            csumField.add("[Calculated Checksum: " + hexString(calcCrc, 8) + "]", o + 8, 4);
        }

        auto packetList = [](const std::vector<uint32_t> &packets) {
            std::string out;
            for (uint32_t n: packets) out += (out.empty() ? "" : ", ") + std::to_string(n);
            return out;
        };

        // Add chunk nodes
        for (const auto &chunk: chunks) {
            size_t co = ctx.offsetOf(data + chunk.off);
            std::string cname = sctpChunkTypeName(chunk.type);
            Field &cf = l.add("Chunk: " + cname + " (Type: " + std::to_string(chunk.type) +
                              ", Length: " + std::to_string(chunk.length) + ")", co, chunk.shown);
            cf.add("Type: " + std::to_string(chunk.type) + " (" + cname + ")", co, 1);
            const auto *cp = bytes + chunk.off;
            const bool isData = chunk.type == sctp::kData || chunk.type == sctp::kIData;
            sctp::DataHeader dh;
            const bool haveData = isData && sctp::readDataHeader(cp, chunk.shown, chunk.length, dh, nullptr);
            if (haveData) {
                sctp::addDataHeaderFields(cf, dh, co, chunk.length);
                const size_t userLen = chunk.shown - dh.headerLength;
                if (userLen > 0) {
                    cf.add("User Data (" + std::to_string(userLen) + " bytes)" + (chunk.shown < chunk.length ? " [cut]" : ""), co + dh.headerLength, userLen);
                }
                if (chunk.hasData && ctx.sessions) {
                    // the totals of the stream in this direction (final, so the same whichever packet is looked at)
                    if (const SctpStreamStats *st = ctx.sessions->sctpTable().stream(pack.source, srcPort, pack.destination, dstPort, dh.stream)) {
                        cf.add("[Stream " + std::to_string(dh.stream) + " in this direction: " + std::to_string(st->chunks) + " DATA chunk(s), " +
                               std::to_string(st->bytes) + " bytes, " + std::to_string(st->messages) + " message end(s) in the capture; " +
                               std::to_string(ctx.sessions->sctpTable().streamCount(pack.source, srcPort, pack.destination, dstPort)) + " stream(s) in use]");
                    }
                }
                if (chunk.fragment) {
                    const char *part = dh.begin ? "first" : dh.end ? "last" : "middle";
                    const std::string seq = std::string(dh.idata ? "FSN " : "TSN ") + std::to_string(dh.sequence());
                    cf.add(std::string("[SCTP fragment of a user message (") + part + ", " + seq + ")]");
                    if (chunk.message) {
                        Field &m = cf.add("[Reassembled SCTP message (" + std::to_string(chunk.message->data.size()) + " bytes) from frame(s) " +
                                          packetList(chunk.message->packets) + "]");
                        m.add("Stream Identifier: " + std::to_string(chunk.message->stream));
                        m.add(std::string(chunk.message->idata ? "Message Identifier: " : "Stream Sequence Number: ") + std::to_string(chunk.message->ssn));
                        const std::string name = sctp::ppidName(chunk.message->ppid);
                        m.add("Payload Protocol Identifier: " + std::to_string(chunk.message->ppid) + (name.empty() ? "" : " (" + name + ")"));
                        m.add("Reassembled data (" + std::to_string(chunk.message->data.size()) + " bytes): " + asciiPreview(chunk.message->data.data(), chunk.message->data.size()));
                    } else if (chunk.ref) {
                        if ((chunk.ref->flags & SctpFragmentRef::kCompletesHere) == 0 && chunk.ref->completedIn) {
                            cf.add(chunk.ref->completedIn == number ? std::string("[The message is reassembled by another chunk of this packet]")
                                                                    : "[Reassembled in #" + std::to_string(chunk.ref->completedIn) + "]");
                        }
                        if (chunk.ref->flags & SctpFragmentRef::kRetransmission)
                            cf.add("[Retransmission of a fragment seen in #" + std::to_string(chunk.ref->original) + "]");
                        if (chunk.ref->flags & SctpFragmentRef::kConflict)
                            cf.add("[Expert Info (Warning/Protocol): the fragment carries other bytes than the first copy]");
                        if (chunk.ref->flags & SctpFragmentRef::kRejected)
                            cf.add("[Expert Info (Warning/Protocol): the message would be larger than 16 MiB: not reassembled]");
                    } else if (chunk.lost) {
                        cf.add("[Expert Info (Warning/Protocol): the SCTP session table lost state; the fragment is not reassembled]");
                    }
                }
            } else {
                cf.add("Flags: " + hexString(chunk.flags, 2), co + 1, 1);
                cf.add("Length: " + std::to_string(chunk.length), co + 2, 2);   // shown >= 4: the loop needs 4 bytes
                if (!isData) sctp::decodeBody(&cf, chunk.type, chunk.flags, cp, chunk.shown, chunk.length, co);
            }
        }
    }
}

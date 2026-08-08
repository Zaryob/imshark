// SCTP (Stream Control Transmission Protocol, RFC 9260 / 4960) dissector:
// Common header + CRC-32C verification + the chunks with their bodies and parameters (sctp_chunks.cpp).
#include "sctp.h"

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
    };
    std::vector<ChunkInfo> chunks;
    bool chunkBeyondPacket = false;
    const char *malformed = nullptr;

    while (offset + 4 <= length) {
        uint8_t ctype = bytes[offset];
        uint8_t cflags = bytes[offset + 1];
        uint16_t clen = readU16(bytes + offset + 2);

        if (firstChunkType == 0xFF) firstChunkType = ctype;

        const size_t room = length - offset;
        chunks.push_back({ctype, cflags, clen, clen < room ? clen : room, offset});

        if (!chunkSummary.empty()) chunkSummary += ", ";
        chunkSummary += sctpChunkTypeName(ctype);

        if (clen < 4) {
            malformed = "Invalid SCTP chunk length (< 4)";
            break;
        }
        // the body of the chunk (what lies inside the packet); a problem with it is reported after the framing ones
        const char *bodyProblem = nullptr;
        if (ctype == sctp::kData || ctype == sctp::kIData) {
            sctp::DataHeader dh;
            sctp::readDataHeader(bytes + offset, chunks.back().shown, clen, dh, &bodyProblem);
        } else {
            bodyProblem = sctp::decodeBody(nullptr, ctype, cflags, bytes + offset, chunks.back().shown, clen, 0);
        }
        if (clen > room) {
            chunkBeyondPacket = true;
            malformed = "SCTP chunk length extends beyond the packet";
            break;
        }
        if (bodyProblem && !malformed) malformed = bodyProblem;

        // Advance with 4-byte padding per RFC 4960 section 3.2
        offset += (static_cast<size_t>(clen) + 3) & ~static_cast<size_t>(3);
    }
    // a chunk cut off by the end of the capture: the CRC covers bytes that are not there
    if (chunkBeyondPacket) pack.checksum_state = static_cast<uint8_t>((pack.checksum_state & ~0x0c) | (kChecksumUnverified << 2));

    pack.app_type = firstChunkType;
    pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) + " [" +
                (chunkSummary.empty() ? "No chunks" : chunkSummary) + "]";
    if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Stream Control Transmission Protocol, Src Port: " + std::to_string(srcPort) +
                                ", Dst Port: " + std::to_string(dstPort), o, length);

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
            } else {
                cf.add("Flags: " + hexString(chunk.flags, 2), co + 1, 1);
                cf.add("Length: " + std::to_string(chunk.length), co + 2, 2);   // shown >= 4: the loop needs 4 bytes
                if (!isData) sctp::decodeBody(&cf, chunk.type, chunk.flags, cp, chunk.shown, chunk.length, co);
            }
        }
    }
}

#pragma once

// SCTP chunk bodies and parameters (RFC 9260 section 3, RFC 8260 I-DATA, RFC 3758 FORWARD-TSN, RFC 4895 AUTH parameters,
// RFC 5061 supported extensions). The functions only read bytes inside [chunk, chunk + shown): `shown` is what lies inside the
// packet, `stated` the chunk's own Length field. A body problem is reported only as text; the caller decides what it means.

#include <cstddef>
#include <cstdint>
#include <string>

#include <packet/packet_info.h>

namespace dissect::sctp {
    std::string chunkTypeName(uint8_t type);
    /// IANA "SCTP Payload Protocol Identifiers"; empty for a value this table does not know.
    std::string ppidName(uint32_t ppid);

    constexpr uint8_t kData = 0, kInit = 1, kInitAck = 2, kSack = 3, kHeartbeat = 4, kHeartbeatAck = 5, kAbort = 6, kShutdown = 7,
                      kShutdownAck = 8, kError = 9, kCookieEcho = 10, kCookieAck = 11, kEcne = 12, kCwr = 13, kShutdownComplete = 14,
                      kAuth = 15, kIData = 64, kForwardTsn = 192, kIForwardTsn = 194;

    /// The fixed part of a DATA (RFC 9260 3.3.1) or I-DATA (RFC 8260 2.1) chunk.
    struct DataHeader {
        bool idata = false;
        bool begin = false, end = false, unordered = false, immediate = false;   // B, E, U, I flags
        uint32_t tsn = 0;
        uint16_t stream = 0;
        uint32_t ssn = 0;            // DATA: Stream Sequence Number; I-DATA: Message Identifier
        bool hasPpid = false;        // DATA always, I-DATA only in the first fragment (B bit)
        uint32_t ppid = 0;
        uint32_t fsn = 0;            // I-DATA: Fragment Sequence Number (0 in the first fragment, which carries the PPID instead)
        size_t headerLength = 0;     // 16 (DATA) or 20 (I-DATA)
        /// The number by which the fragments of one message follow each other: the TSN (DATA) or the FSN (I-DATA).
        uint32_t sequence() const { return idata ? fsn : tsn; }
    };

    /// Reads the header when `shown` holds all of it. A chunk whose stated length is shorter than the header is reported
    /// through `problem` (and false is returned).
    bool readDataHeader(const uint8_t *chunk, size_t shown, size_t stated, DataHeader &out, const char **problem);

    /// Adds the header fields of a DATA / I-DATA chunk to `cf`; `offset` is the chunk's position in the frame.
    void addDataHeaderFields(packet::Field &cf, const DataHeader &h, size_t offset, size_t stated);

    /// Decodes the body of any chunk but DATA / I-DATA into `tree` (null: validate only). Returns the problem found (nullptr: none).
    const char *decodeBody(packet::Field *tree, uint8_t type, uint8_t flags, const uint8_t *chunk, size_t shown, size_t stated, size_t offset);
} // namespace dissect::sctp

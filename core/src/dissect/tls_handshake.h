#pragma once

// The pieces of TLS and DTLS that are the same in both: names of content types, versions, cipher suites and alerts,
// the hello fields, the extensions block and the Certificate message, and the decoder of one handshake message body.
// tls.cpp (records over TCP) and dtls.cpp (records over UDP, fragments reassembled by the datagram reassembler) both
// build on this, so a hello, an extension or a certificate looks the same whatever carried it.
//
// The decoders work on a `Joined` payload: bytes that may come from several records or fragments, each part remembering
// where it sits in the frame so the nodes of the field tree point at real bytes (a part that has no place in the frame,
// such as a reassembled message, is zeroed by the caller afterwards).

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <packet/packet_info.h>

namespace dissect::tlsparse {
    const char *contentTypeName(uint8_t type);
    /// `dtls` adds the types only DTLS has (3 = HelloVerifyRequest).
    const char *handshakeName(uint8_t type, bool dtls = false);
    /// "TLS 1.2", "DTLS 1.2", ... (or the hex value).
    std::string versionName(uint16_t version);
    std::string cipherName(uint16_t suite);
    /// nullptr for an alert description that has no name here.
    const char *alertName(uint8_t description);
    std::string join(const std::vector<std::string> &items, size_t limit = 24);

    /// Handshake payload that has been put together from one or more records, and where each part sits in the frame.
    struct Joined {
        std::string bytes;
        std::vector<std::pair<size_t, size_t>> parts;   // {position in `bytes`, offset in the frame}

        void append(const char *p, size_t n, size_t frameOffset) {
            parts.push_back({bytes.size(), frameOffset});
            bytes.append(p, n);
        }
        // Offset in the frame of byte `pos` (clamped into the part it falls in).
        size_t frame(size_t pos) const;
        // How many bytes starting at `pos` stay inside one part of the frame
        size_t contiguous(size_t pos, size_t length) const;
    };

    struct Hello {
        std::string serverName;
        std::string alpn;
        std::string subject;             // common name of the first certificate seen
        uint16_t supportedVersion = 0;   // highest from the supported_versions extension
        uint16_t cipher = 0;             // ServerHello's chosen suite
        uint16_t version = 0;            // legacy version field
        bool earlyData = false;          // ClientHello with the early_data extension (0-RTT)
        uint8_t helloType = 0;           // 1 / 2 when a plausible ClientHello / ServerHello was read (0 = none)
        int cookieLength = -1;           // DTLS ClientHello / HelloVerifyRequest: length of the cookie (-1 = none read)
        std::array<uint8_t, 32> random{};   // that hello's random
    };

    // Walks the extensions block bytes[at, at+n); fills `h` and (when `tree`) adds nodes
    void parseExtensions(const Joined &j, size_t at, size_t n, bool client, Hello &h, packet::Field *tree);

    // Certificate message body [at, at+n): TLS 1.2 (list) or TLS 1.3 (request context + list with extensions)
    void parseCertificates(const Joined &j, size_t at, size_t n, Hello &h, packet::Field *tree);

    /// Decodes the body of one handshake message of type `type` that sits at `base` in `j`: `avail` bytes of it are present
    /// and `complete` says the whole message is there (only a complete hello counts as
    /// one: a handshake record that is really encrypted can start with these bytes by chance). Adds nodes to `tree` (the
    /// node of the message, may be null) and returns the name for the Info column. `dtls` selects the DTLS hello layout
    /// (cookie after the session id), DTLS versions and HelloVerifyRequest.
    std::string decodeHandshakeBody(const Joined &j, uint8_t type, size_t base, size_t avail, bool complete, Hello &hello,
                                    packet::Field *tree, bool dtls = false);
} // namespace dissect::tlsparse

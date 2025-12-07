#pragma once

// "Follow stream": the payload of one TCP or UDP conversation, reassembled in order.

#include <cstdint>
#include <string>
#include <vector>

#include <capture_reader.h>
#include <dissect/session.h>
#include <packet/packet_info.h>
#include <tls/keylog.h>

namespace stream {
    enum class Direction { AtoB, BtoA };

    /// A run of payload bytes flowing in one direction. A is the sender of the first packet.
    struct Chunk {
        Direction direction = Direction::AtoB;
        std::string data;
        uint64_t missingBefore = 0;   // bytes that were never captured right before this chunk (TCP gaps)
        int firstPacket = 0;          // number of the packet that delivered the first byte
    };

    struct Stream {
        bool tcp = true;
        std::string addressA, addressB;
        uint16_t portA = 0, portB = 0;
        std::vector<Chunk> chunks;
        int packets = 0;              // packets of the conversation
        uint64_t bytesAtoB = 0, bytesBtoA = 0;
        uint64_t missingBytes = 0;    // total size of the TCP gaps
        bool truncated = false;       // stopped at the size limit
    };

    /// Indices (capture order) of all packets of the TCP/UDP conversation that `packets[index]` belongs to;
    /// empty if that packet is neither TCP nor UDP (or `index` is out of range).
    std::vector<uint32_t> conversationPackets(const std::vector<packet::PacketInfo> &packets, uint32_t index);

    /// Reads the payload of `indices` (ascending capture order) from `capturePath` and reassembles it:
    /// TCP segments are put in sequence order (out-of-order data is held back until the gap fills,
    /// retransmissions and overlaps are dropped, holes become `missingBefore`), UDP datagrams are taken as
    /// they come. Stops after `maxBytes` of output. Returns false if cancelled or the file cannot be read.
    bool reassemble(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                    const std::vector<uint32_t> &indices, Stream &out, core::ScanControl *control = nullptr,
                    uint64_t maxBytes = 256ull * 1024 * 1024);

    // ---- "TLS (decrypted)": the application data of a TLS connection ---------------------------------------------------

    /// What the decryption of a followed conversation needs, taken from the session tables of the loaded capture (cheap to
    /// copy into a background job).
    struct TlsStreamSetup {
        bool available = false;        // a TLS session whose ClientHello was captured exists for the conversation
        uint16_t version = 0, cipherSuite = 0;
        tls::ClientRandom clientRandom{}, serverRandom{};
        bool haveKeys = false;
        tls::KeyEntry keys;
        bool aIsClient = true;         // endpoint A of the Stream (sender of the first packet) is the TLS client
    };

    /// Looks the conversation (as `reassemble` names its endpoints) up in the TLS session tables. When several TLS
    /// connections used the same endpoints the newest one is taken.
    TlsStreamSetup tlsStreamSetup(const dissect::SessionTables &sessions, const std::string &addressA, uint16_t portA, const std::string &addressB,
                                  uint16_t portB);

    struct TlsStreamResult {
        bool ok = false;               // `out` holds decrypted application data
        std::string note;              // why not, or what was left out ("2 records could not be decrypted ...")
        size_t records = 0;            // protected records seen
        size_t decrypted = 0;          // of them decrypted
        size_t failed = 0;             // wrong key / malformed / no key
        size_t skipped = 0;            // not tried: TCP data is missing before them
    };

    /// Decrypts the TLS records of `raw` (the result of `reassemble` for a TCP conversation) in stream order and keeps the
    /// application data: `out` is a Stream with the same endpoints whose chunks are the plaintext, interleaved the way the
    /// records were sent. Handshake messages, alerts and records that cannot be opened are left out (and counted in
    /// `result`); data after a hole in a direction is not decrypted (the record numbers are lost), it is not reported as a
    /// wrong key. Nothing in `out` is plaintext that the AEAD tag did not verify.
    bool decryptTlsStream(const Stream &raw, const TlsStreamSetup &setup, Stream &out, TlsStreamResult &result);
} // namespace stream

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {
    /// One capture interface (pcapng IDB, or the single interface of a classic pcap file).
    struct InterfaceInfo {
        uint32_t linkType = 1;
        uint32_t snapLen = 0;
        uint64_t ticksPerSecond = 1000000;  // timestamp resolution (ticks per second)
        std::string name, description;
        uint64_t packets = 0;               // packets of this interface in the file
        bool hasStats = false;              // an Interface Statistics Block was present
        uint64_t received = 0, dropped = 0; // from the statistics block (if given)
        uint8_t fcsLength = 0;              // FCS bytes appended to each frame (0 = unknown/none)
    };

    struct NameRecord {
        std::string address;
        std::string name;
    };

    /// Secrets type of a pcapng Decryption Secrets Block that holds a TLS key log ("TLSK").
    constexpr uint32_t kSecretsTypeTlsKeyLog = 0x544c534b;

    /// One pcapng Decryption Secrets Block (block type 0x0000000A): the secrets as they are in the file.
    struct DecryptionSecrets {
        uint32_t type = 0;                   // secrets type (kSecretsTypeTlsKeyLog = NSS key log text)
        std::string data;                    // the secrets, without padding
    };

    /// Metadata of a capture file that is not part of any packet.
    struct CaptureInfo {
        std::string format;                  // "pcap" / "pcapng" with byte order and precision
        uint64_t fileSize = 0;               // size of the file the packets are read from (decompressed size for .gz)
        std::string container;               // "gzip" if the file was opened from a compressed copy
        uint64_t compressedSize = 0;         // size of the compressed file (0 if not compressed)
        uint32_t sections = 0;               // pcapng section header blocks
        std::string comment, hardware, os, application; // first section header
        std::vector<InterfaceInfo> interfaces;
        std::vector<NameRecord> names;       // name resolution blocks (capped)
        std::unordered_map<uint32_t, std::string> packetComments; // by packet number
        std::vector<DecryptionSecrets> decryptionSecrets;   // pcapng Decryption Secrets Blocks (kept to write them out again)
        size_t tlsKeyLogSecrets = 0;         // secrets read from the TLS key log blocks (they are in the session tables' key store)
        size_t tlsKeyLogMalformed = 0;       // lines of those blocks that were not valid key log lines
        size_t tlsKeyLogDropped = 0;         // valid secrets that were not stored because the key store is full
    };
} // namespace core

#pragma once

// Writing packets out: capture files (pcap / pcapng) and tables (CSV / JSON).

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include <capture_info.h>
#include <capture_reader.h>
#include <packet/packet_info.h>

namespace exporter {
    enum class Format { Pcap, Pcapng, Csv, Json };

    const char *formatName(Format f);        // "pcapng (Wireshark)", "CSV", ...
    const char *formatExtension(Format f);   // ".pcapng", ".pcap", ".csv", ".json"
    bool isCaptureFormat(Format f);

    /// Table output (the columns of the packet list). `indices` selects and orders the rows.
    void writeCsv(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices);
    void writeJson(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices,
                   double captureStartEpoch);

    /// RFC 4180 field quoting: always quoted, quotes doubled.
    std::string csvField(const std::string &text);
    /// JSON string literal with escapes.
    std::string jsonString(const std::string &text);

    /// Writes the packets in `indices` to `outPath` in `format`. Capture formats read the frames from
    /// `capturePath`; timestamps are `captureStartEpoch + packet.time` with microsecond resolution.
    /// Classic pcap needs one link type for all packets (use pcapng otherwise). Returns false and sets
    /// `error` on failure; false without an error text if cancelled through `control`. `secrets` (pcapng only) are
    /// written as Decryption Secrets Blocks in front of the packets, so a decrypted TLS capture stays decryptable.
    bool exportPackets(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                       const std::vector<uint32_t> &indices, double captureStartEpoch, Format format,
                       const std::string &outPath, std::string &error, core::ScanControl *control = nullptr,
                       const std::vector<core::DecryptionSecrets> *secrets = nullptr);
} // namespace exporter

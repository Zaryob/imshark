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

    /// Table output (the columns of the packet list). `indices` selects and orders the rows. Times are written with
    /// `fractionDigits` decimals: 6 for microsecond captures, 9 for nanosecond ones (see exportPackets). With `info`
    /// (holding the exact capture start) JSON's time_epoch is computed in integers, so no digit is lost to a double.
    void writeCsv(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices,
                  int fractionDigits = 6);
    void writeJson(std::ostream &out, const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &indices,
                   double captureStartEpoch, int fractionDigits = 6, const core::CaptureInfo *info = nullptr);

    /// RFC 4180 field quoting: always quoted, quotes doubled.
    std::string csvField(const std::string &text);
    /// JSON string literal with escapes.
    std::string jsonString(const std::string &text);

    /// Writes the packets in `indices` to `outPath` in `format`. Capture formats read the frames from
    /// `capturePath`; timestamps are `captureStartEpoch + packet.time` with microsecond resolution, unless `info`
    /// is given and says the capture has nanosecond timestamps (an interface finer than a microsecond): then
    /// pcap is written with the nanosecond magic, pcapng with if_tsresol = 9 on every interface (so mixed-resolution
    /// interfaces are all written at the finest one; microsecond values are exact in it) and CSV/JSON times with nine
    /// decimals. With `info->hasStart` the instants are computed from the exact start (integer seconds + nanoseconds)
    /// instead of the double `captureStartEpoch`, which resolves only ~240 ns.
    /// The destination must not be the input capture or an alias of it. Classic pcap needs one link type for
    /// all packets (use pcapng otherwise). Returns false and sets
    /// `error` on failure; false without an error text if cancelled through `control`. `secrets` (pcapng only) are
    /// written as Decryption Secrets Blocks in front of the packets, so a decrypted TLS capture stays decryptable.
    bool exportPackets(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                       const std::vector<uint32_t> &indices, double captureStartEpoch, Format format,
                       const std::string &outPath, std::string &error, core::ScanControl *control = nullptr,
                       const std::vector<core::DecryptionSecrets> *secrets = nullptr, const core::CaptureInfo *info = nullptr);
} // namespace exporter

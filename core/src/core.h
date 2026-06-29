#pragma once

#include <cstdint>
#include <string>
#include <filesystem>
#include <vector>

#include <packet/packet_info.h>
#include <capture_info.h>
#include <load_control.h>
#include <packet/packet_parser.h>
#include <dissect/session.h>
#include <io/capture_file.h>

namespace core {
    /// Supported and recognized capture file formats (ROADMAP B5).
    enum class FileFormat {
        Unknown = 0,
        Pcap,
        Pcapng,
        NetMon,     // Microsoft Network Monitor (.cap)
        Snoop,      // Sun snoop
        Erf,        // Endace ERF
        Iptrace,    // AIX iptrace (v1.0 / v2.0)
        Gzip,       // gzip wrapper around a capture file (unpacked by the loader before reading)
    };

    /// Returns the human-readable display name of a capture file format.
    const char *formatName(FileFormat fmt);

    /// Identifies the format of a file from its initial bytes/magic number.
    FileFormat detectFileFormat(const std::string &filepath);

    /// Diagnoses a file of a recognized format that cannot be read: "Unsupported file format: <Name>".
    /// Returns an empty string for formats that are readable and for Unknown.
    std::string unsupportedFormatDiagnostic(FileFormat fmt);

    /// Diagnoses a file that matched no known format: "Unsupported file format: unknown magic number 7f 45 4c 46".
    /// Empty if fewer than 4 bytes are given (too short to carry a magic number).
    std::string unknownFormatDiagnostic(const uint8_t *buf, size_t len);

    /// Reads capture files (classic pcap and pcapng) into a list of parsed packets.
    ///
    /// Both entry points return true if the file could be read. On failure `message` describes the
    /// problem; on partial success (e.g. a truncated last packet) they return true, keep the packets
    /// that were read and describe the problem in `message`. `message` is empty when everything is fine.
    /// Malformed input never terminates the process.
    ///
    /// `control` (optional) reports progress and lets another thread cancel the load; a cancelled load
    /// returns false with message "Cancelled" and leaves the packets read so far in `packets`.
    /// Interprets a std::string as UTF-8 (what the file dialog returns) when building a path. Needed on
    /// Windows, where a plain std::string path would go through the ANSI code page.
    inline std::filesystem::path pathFromUtf8(const std::string &utf8) {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(utf8.data()), utf8.size()));
    }

    /// Reads the captured frame of `summary` back from the capture file it was loaded from.
    bool readPacketBytes(const std::string &filepath, const packet::PacketInfo &summary, std::vector<char> &out);

    /// Builds the full view of one packet of a loaded capture: copies the summary, reads the frame bytes
    /// from `filepath` and dissects it again, this time producing the protocol field tree. (While loading
    /// only summaries are kept so that large captures do not exhaust memory.)
    ///
    /// `allPackets` (the whole loaded capture) is only needed for the last fragment of a reassembled IPv4
    /// datagram: the other fragments are found in it and read from the file.
    bool buildPacketDetails(const std::string &filepath, const packet::PacketInfo &summary, packet::PacketInfo &details,
                            const std::vector<packet::PacketInfo> *allPackets = nullptr, const CaptureInfo *info = nullptr,
                            const dissect::Registry *registry = nullptr,
                            const dissect::SessionTables *sessions = nullptr);

    /// Reports time relative to the first packet that was seen. The split into whole seconds and a
    /// fraction keeps full precision even where long double is just a double (MSVC).
    struct TimeBase {
        bool set = false;
        uint64_t baseSeconds = 0;
        double baseFraction = 0;

        double relative(uint64_t seconds, uint64_t fractionTicks, uint64_t ticksPerSecond) {
            const double fraction = static_cast<double>(fractionTicks) / static_cast<double>(ticksPerSecond);
            if (!set) {
                set = true;
                baseSeconds = seconds;
                baseFraction = fraction;
            }
            return static_cast<double>(static_cast<int64_t>(seconds - baseSeconds)) + (fraction - baseFraction);
        }

        double startEpoch() const { return set ? static_cast<double>(static_cast<int64_t>(baseSeconds)) + baseFraction : 0.0; }
    };

    class FileProcessor {
        packet::PacketParser parser;
    public:
        /// `registry` selects the dissectors (default: the built-in ones); it must outlive the processor.
        explicit FileProcessor(const dissect::Registry &registry = dissect::Registry::builtin()) : parser(registry) {}

        bool processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                             std::string &message, LoadControl *control = nullptr);

        bool processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                               std::string &message, LoadControl *control = nullptr);

        /// Universal file loader that inspects the file header and dispatches to the appropriate loader,
        /// or provides specific diagnostic messages for known unsupported file formats (B5).
        bool processFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                         std::string &message, LoadControl *control = nullptr);

        /// Incremental ("live") use: packets arrive one at a time while a capture file is still being written.
        /// beginLive() starts a new capture (clears the session tables, the time base and the metadata; `linkType`
        /// and `snapLen` describe the single interface). appendLivePacket() then dissects one more frame through
        /// the same per-packet path the file loaders use (addPacket: summary parse, IP/TCP reassembly annotation of
        /// earlier packets, session tables), so the summaries equal those of loading the finished file. `tsSeconds` /
        /// `tsMicros` is the capture timestamp (microsecond resolution), `fileOffset` the offset of the frame bytes
        /// in the file that detail building reads later. Earlier entries of `packets` may be amended (reassembly
        /// annotations), exactly as during a file load. The session tables are only unfrozen while a packet is
        /// dissected, so detail building (Replay) between two packets sees frozen tables. `amended` (optional) receives the
        /// indices (into `packets`) of the earlier entries whose summary was edited in place by this packet (the
        /// "[Reassembled in #n]" annotations), so a caller that caches filter/colour results can refresh just those rows.
        void beginLive(uint32_t linkType, uint32_t snapLen);
        void appendLivePacket(std::vector<packet::PacketInfo> &packets, uint64_t tsSeconds, uint32_t tsMicros, uint32_t linkType,
                              uint64_t fileOffset, uint32_t originalLength, const std::vector<char> &frame,
                              std::vector<uint32_t> *amended = nullptr);

        /// UTC epoch seconds of the first packet of the last processed file (0 if there was none).
        double captureStartEpoch() const { return captureStart_; }

        /// Metadata of the last processed file: format, interfaces, statistics, name records, packet comments.
        const CaptureInfo &captureInfo() const { return info_; }

        /// Session tables populated during capture load (FTP-DATA, TFTP, etc.)
        const dissect::SessionTables &sessions() const { return parser.sessions(); }
        dissect::SessionTables &sessions() { return parser.sessions(); }

    private:
        /// Loads `filepath` through `reader`: the part of a load that is the same for every capture file format.
        bool load(io::CaptureFileReader &reader, const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                  std::string &message, LoadControl *control);

        double captureStart_ = 0;
        CaptureInfo info_;
        TimeBase liveTime_;
    };
} // namespace core

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

namespace core {
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

    class FileProcessor {
        packet::PacketParser parser;
    public:
        /// `registry` selects the dissectors (default: the built-in ones); it must outlive the processor.
        explicit FileProcessor(const dissect::Registry &registry = dissect::Registry::builtin()) : parser(registry) {}

        bool processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                             std::string &message, LoadControl *control = nullptr);

        bool processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                               std::string &message, LoadControl *control = nullptr);

        /// UTC epoch seconds of the first packet of the last processed file (0 if there was none).
        double captureStartEpoch() const { return captureStart_; }

        /// Metadata of the last processed file: format, interfaces, statistics, name records, packet comments.
        const CaptureInfo &captureInfo() const { return info_; }

        /// Session tables populated during capture load (FTP-DATA, TFTP, etc.)
        const dissect::SessionTables &sessions() const { return parser.sessions(); }
        dissect::SessionTables &sessions() { return parser.sessions(); }

    private:
        double captureStart_ = 0;
        CaptureInfo info_;
    };
} // namespace core

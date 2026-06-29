#include <core.h>

#include <capture_reader.h>
#include <io/format_registry.h>

#include <algorithm>
#include <exception>
#include <cstring>
#include <fstream>

namespace {
    /// Reserves room for the packets a file of `fileSize` bytes can hold at most (`minRecordBytes` is the smallest
    /// record: header plus a minimal frame). Growing a vector by doubling copies it again and again and peaks at
    /// about twice its final size; reserving costs only address space, because pages that are never written do not
    /// count as used memory. Failing to reserve is harmless: the vector then simply grows as usual.
    void reservePackets(std::vector<packet::PacketInfo> &packets, uint64_t fileSize, uint64_t minRecordBytes) {
        constexpr uint64_t kMaxReserved = 32ull << 20; // elements: bounds the address space for huge files
        const uint64_t estimate = std::min<uint64_t>(fileSize / minRecordBytes + 16, kMaxReserved);
        try {
            if (estimate > packets.capacity()) packets.reserve(packets.size() + static_cast<size_t>(estimate));
        } catch (const std::exception &) {
        }
    }

    uint64_t fileSizeOf(std::ifstream &file) {
        file.seekg(0, std::ios::end);
        const auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        return size < 0 ? 0 : static_cast<uint64_t>(size);
    }

    /// Publishes progress; returns true if the load should stop because a cancel was requested.
    bool reportProgress(core::LoadControl *control, uint64_t bytesProcessed, size_t packetsLoaded) {
        if (!control) return false;
        control->bytesProcessed = bytesProcessed;
        control->packetsLoaded = packetsLoaded;
        return control->cancelRequested;
    }

    // Keeps only the summary: the frame bytes stay in the file (file_offset/captured_length) and the field
    // tree is rebuilt on demand (see core::buildPacketDetails).
    void addPacket(packet::PacketParser &parser, std::vector<packet::PacketInfo> &packets,
                   double time, uint32_t linkType, uint64_t fileOffset, uint32_t originalLength,
                   const std::vector<char> &data, bool hasComment = false, uint8_t fcsLength = 0,
                   std::vector<uint32_t> *amended = nullptr) {
        packet::PacketInfo pack(static_cast<int>(packets.size()) + 1);
        pack.time = time;
        pack.link_type = linkType;
        pack.file_offset = fileOffset;
        pack.captured_length = static_cast<uint32_t>(data.size());
        pack.frame_length = originalLength;
        pack.has_comment = hasComment;
        pack.fcs_length = fcsLength;
        parser.parsePacket(pack, data, dissect::ParseMode::Summary);
        // this packet completed an IPv4 datagram: tell the earlier fragments where it was reassembled
        for (const auto &[fragment, completing]: parser.takeCompletedReassemblies()) {
            if (fragment >= 1 && fragment <= packets.size()) {
                auto &f = packets[fragment - 1];
                f.reassembled_in = completing;
                f.info += " [Reassembled in #" + std::to_string(completing) + "]";
                if (amended) amended->push_back(static_cast<uint32_t>(fragment - 1));
            }
        }
        // this packet completed a TCP message: tell the earlier segments of it where it was reassembled
        for (const auto &[segment, completing]: parser.takeCompletedTcpPdus()) {
            if (segment >= 1 && segment <= packets.size() && (packets[segment - 1].tcp_pdu_state == 1 || packets[segment - 1].tcp_pdu_state == 4)) {
                auto &s = packets[segment - 1];
                s.tcp_reassembled_in = completing;
                s.info += " [Reassembled in #" + std::to_string(completing) + "]";
                if (amended) amended->push_back(static_cast<uint32_t>(segment - 1));
            }
        }
        // this packet completed a message that was split into datagram fragments: the earlier fragments say where
        for (const auto &[earlier, completing]: parser.takeCompletedDatagramMessages()) {
            if (earlier >= 1 && earlier <= packets.size()) {
                packets[earlier - 1].info += " [Reassembled in #" + std::to_string(completing) + "]";
                if (amended) amended->push_back(static_cast<uint32_t>(earlier - 1));
            }
        }
        packets.emplace_back(std::move(pack));
    }
} // namespace

const char *core::formatName(FileFormat fmt) {
    if (const auto *f = io::findFormat(fmt)) return f->name;
    return "Unknown format";
}

std::string core::unsupportedFormatDiagnostic(FileFormat fmt) {
    const auto *f = io::findFormat(fmt);
    if (!f || f->makeReader) return "";
    if (f->container) return std::string("Unsupported file format: ") + f->name + " compressed capture (decompress it first)";
    return std::string("Unsupported file format: ") + f->name;
}

std::string core::unknownFormatDiagnostic(const uint8_t *buf, size_t len) {
    if (len < 4) return "";
    static const char *digits = "0123456789abcdef";
    std::string text = "Unsupported file format: unknown magic number";
    for (size_t i = 0; i < 4; ++i) {
        text += ' ';
        text += digits[buf[i] >> 4];
        text += digits[buf[i] & 15];
    }
    return text;
}

core::FileFormat core::detectFileFormat(const std::string &filepath) {
    std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
    if (!file.is_open()) return FileFormat::Unknown;
    uint8_t buf[io::kProbeBytes] = {0};
    file.read(reinterpret_cast<char *>(buf), sizeof(buf));
    return io::identifyFormat(buf, static_cast<size_t>(file.gcount()));
}

/// FILE LOADING: the format specific part lives in the CaptureFileReaders (io/), this is the part all formats share.

bool core::FileProcessor::load(io::CaptureFileReader &reader, const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                               std::string &message, LoadControl *control) {
    message.clear();
    captureStart_ = 0;
    parser.sessions().clear();
    std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
    if (!file.is_open()) {
        message = "Failed to open file: " + filepath;
        return false;
    }
    const uint64_t fileSize = fileSizeOf(file);
    if (control) control->totalBytes = fileSize;

    io::ReaderContext context{info_, parser.sessions(), fileSize};
    if (!reader.open(file, context, message)) return false;

    TimeBase timeBase;
    double lastTime = 0;
    const size_t firstPacket = packets.size();
    reservePackets(packets, fileSize, reader.minRecordBytes());

    io::CaptureRecord record;
    io::ReadIssue issue;
    while (true) {
        const auto status = reader.next(record, issue);
        if (status == io::CaptureFileReader::Status::End) {
            message = issue.message;
            break;
        }
        if (status == io::CaptureFileReader::Status::Error) {
            message = issue.message;
            return issue.keepRecords;
        }
        // a record without a timestamp (pcapng simple packet) takes the time of the previous one
        if (record.hasTimestamp) lastTime = timeBase.relative(record.seconds, record.fraction, record.ticksPerSecond);
        const bool hasComment = !record.comment.empty();
        if (hasComment) info_.packetComments[static_cast<uint32_t>(packets.size()) + 1] = record.comment;
        if (record.interfaceIndex >= 0) info_.interfaces[static_cast<size_t>(record.interfaceIndex)].packets++;
        addPacket(parser, packets, lastTime, record.linkType, record.fileOffset, record.originalLength, record.frame, hasComment,
                  record.fcsLength);
        if (reportProgress(control, reader.bytesConsumed(), packets.size() - firstPacket)) {
            message = "Cancelled";
            return false;
        }
    }
    captureStart_ = timeBase.startEpoch();
    reportProgress(control, fileSize, packets.size() - firstPacket);
    parser.sessions().freeze();
    reader.finish(message);
    return true;
}

bool core::FileProcessor::processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                          std::string &message, LoadControl *control) {
    const auto reader = io::makePcapReader();
    return load(*reader, filepath, packets, message, control);
}

bool core::FileProcessor::processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                            std::string &message, LoadControl *control) {
    const auto reader = io::makePcapngReader();
    return load(*reader, filepath, packets, message, control);
}

void core::FileProcessor::beginLive(uint32_t linkType, uint32_t snapLen) {
    parser.sessions().clear();
    liveTime_ = TimeBase();
    captureStart_ = 0;
    info_ = CaptureInfo();
    info_.format = "pcap (live capture)";
    InterfaceInfo itf;
    itf.linkType = linkType;
    itf.snapLen = snapLen;
    itf.ticksPerSecond = 1000000;
    info_.interfaces.push_back(itf);
}

void core::FileProcessor::appendLivePacket(std::vector<packet::PacketInfo> &packets, uint64_t tsSeconds, uint32_t tsMicros,
                                           uint32_t linkType, uint64_t fileOffset, uint32_t originalLength,
                                           const std::vector<char> &frame, std::vector<uint32_t> *amended) {
    if (info_.interfaces.empty()) beginLive(linkType, 0);
    const double time = liveTime_.relative(tsSeconds, tsMicros, 1000000);
    captureStart_ = liveTime_.startEpoch();
    parser.sessions().unfreeze();
    addPacket(parser, packets, time, linkType, fileOffset, originalLength, frame, false, 0, amended);
    parser.sessions().freeze();
    info_.interfaces[0].packets++;
    info_.fileSize = fileOffset + frame.size();
}

bool core::FileProcessor::processFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                      std::string &message, LoadControl *control) {
    const FileFormat fmt = detectFileFormat(filepath);
    if (const auto reader = io::makeReader(fmt)) return load(*reader, filepath, packets, message, control);
    std::string diag = unsupportedFormatDiagnostic(fmt);
    if (diag.empty() && fmt == FileFormat::Unknown) {
        std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
        uint8_t buf[io::kProbeBytes] = {0};
        file.read(reinterpret_cast<char *>(buf), sizeof(buf));
        diag = unknownFormatDiagnostic(buf, static_cast<size_t>(file.gcount()));
    }
    if (!diag.empty()) {
        message = diag;
        return false;
    }
    // Too short to carry a magic number (or unreadable): the pcap reader reports it specifically
    return processPcapFile(filepath, packets, message, control);
}

bool core::readPacketBytes(const std::string &filepath, const packet::PacketInfo &summary, std::vector<char> &out) {
    std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
    if (!file.is_open()) return false;
    file.seekg(static_cast<std::streamoff>(summary.file_offset));
    out.resize(summary.captured_length);
    return summary.captured_length == 0 || file.read(out.data(), summary.captured_length).good();
}

namespace {
    // The IPv4 fragment (payload slice + flags) inside a captured Ethernet/link frame
} // namespace

bool core::buildPacketDetails(const std::string &filepath, const packet::PacketInfo &summary, packet::PacketInfo &details,
                              const std::vector<packet::PacketInfo> *allPackets, const CaptureInfo *info,
                              const dissect::Registry *registry, const dissect::SessionTables *sessions) {
    std::vector<char> bytes;
    if (!readPacketBytes(filepath, summary, bytes)) return false;

    details = summary;
    packet::PacketParser parser(registry ? *registry : dissect::Registry::builtin()); // fresh parser: TCP numbers come from `summary` (Replay mode)
    if (sessions) parser.setSessions(const_cast<dissect::SessionTables *>(sessions));

    // the last fragment of a datagram needs the earlier ones to show the reassembled protocols
    std::vector<char> reassembled;
    std::vector<uint32_t> fragmentNumbers;
    if (summary.ip_frag == 2 && allPackets) {
        CaptureReader reader(filepath);
        uint8_t wholeProtocol = 0;
        if (reassembleIpPayload(reader, *allPackets, summary, reassembled, &fragmentNumbers, &wholeProtocol)) {
            parser.setReassembly(&reassembled, &fragmentNumbers, wholeProtocol);
        }
    }

    // the packet that completes a TCP message needs the bytes of the earlier segments
    std::string tcpPdu;
    std::vector<uint32_t> tcpPduPackets;
    if (summary.tcp_pdu_state == 2 && allPackets) {
        CaptureReader reader(filepath);
        if (reassembleTcpPdu(reader, *allPackets, summary, tcpPdu, tcpPduPackets)) parser.setTcpPdu(&tcpPdu, &tcpPduPackets);
    }

    parser.parsePacket(details, bytes, dissect::ParseMode::Replay);
    details.raw_data = std::move(bytes);

    // a comment stored with the packet in the capture file (pcapng) goes right below the frame summary
    if (info && summary.has_comment && !details.fields.empty()) {
        const auto it = info->packetComments.find(static_cast<uint32_t>(summary.number));
        if (it != info->packetComments.end()) details.fields[0].add("Packet comment: " + it->second);
    }
    return true;
}

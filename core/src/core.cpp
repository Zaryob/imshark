#include <core.h>

#include <capture_reader.h>

#include <algorithm>
#include <cstring>
#include <fstream>

namespace {
    // Upper bound for a single record/block; anything larger is treated as corruption
    // instead of being allocated.
    constexpr uint64_t kMaxRecordSize = 256ull * 1024 * 1024;

    constexpr uint32_t kPcapMagicMicro = 0xa1b2c3d4;
    constexpr uint32_t kPcapMagicNano = 0xa1b23c4d;

    constexpr uint32_t kBlockSHB = 0x0A0D0D0A; // Section Header Block
    constexpr uint32_t kBlockIDB = 0x00000001; // Interface Description Block
    constexpr uint32_t kBlockSPB = 0x00000003; // Simple Packet Block
    constexpr uint32_t kBlockEPB = 0x00000006; // Enhanced Packet Block
    constexpr uint32_t kByteOrderMagic = 0x1A2B3C4D;

    constexpr uint16_t kOptEnd = 0;
    constexpr uint16_t kOptIfTsResol = 9;

    constexpr uint32_t kDefaultTicksPerSecond = 1'000'000; // pcapng default: microseconds

    uint16_t swap16(uint16_t v) { return static_cast<uint16_t>((v << 8) | (v >> 8)); }

    uint32_t swap32(uint32_t v) {
        return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
    }

    /// Reads fixed-size integers from a buffer in the byte order of the capture file.
    struct Endian {
        bool swap = false;

        uint16_t u16(const uint8_t *p) const {
            uint16_t v;
            std::memcpy(&v, p, sizeof(v));
            return swap ? swap16(v) : v;
        }

        uint32_t u32(const uint8_t *p) const {
            uint32_t v;
            std::memcpy(&v, p, sizeof(v));
            return swap ? swap32(v) : v;
        }
    };

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

        double startEpoch() const { return set ? static_cast<double>(baseSeconds) + baseFraction : 0.0; }
    };

    struct Interface {
        uint32_t linkType = 1; // LINKTYPE_ETHERNET
        uint32_t snapLen = 0;
        uint64_t ticksPerSecond = kDefaultTicksPerSecond;
    };

    uint64_t remainingBytes(std::ifstream &file, uint64_t fileSize) {
        const auto pos = file.tellg();
        if (pos < 0) return 0;
        return fileSize - std::min<uint64_t>(fileSize, static_cast<uint64_t>(pos));
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
                   const std::vector<char> &data) {
        packet::PacketInfo pack(static_cast<int>(packets.size()) + 1);
        pack.time = time;
        pack.link_type = linkType;
        pack.file_offset = fileOffset;
        pack.captured_length = static_cast<uint32_t>(data.size());
        pack.frame_length = originalLength;
        parser.parsePacket(pack, data, dissect::ParseMode::Summary);
        // this packet completed an IPv4 datagram: tell the earlier fragments where it was reassembled
        for (const auto &[fragment, completing]: parser.takeCompletedReassemblies()) {
            if (fragment >= 1 && fragment <= packets.size()) {
                auto &f = packets[fragment - 1];
                f.reassembled_in = completing;
                f.info += " [Reassembled in #" + std::to_string(completing) + "]";
            }
        }
        packets.emplace_back(std::move(pack));
    }

    /// Parses the options of an Interface Description Block (only if_tsresol is used).
    void parseIdbOptions(const Endian &e, const uint8_t *p, size_t size, Interface &iface) {
        size_t off = 0;
        while (size - off >= 4) {
            const uint16_t code = e.u16(p + off);
            const uint16_t len = e.u16(p + off + 2);
            off += 4;
            if (code == kOptEnd) break;
            const size_t padded = (static_cast<size_t>(len) + 3) & ~static_cast<size_t>(3);
            if (len > size - off) break; // option runs past the block
            if (code == kOptIfTsResol && len == 1) {
                const uint8_t v = p[off];
                const unsigned exponent = v & 0x7f;
                if (v & 0x80) { // power of two
                    if (exponent <= 62) iface.ticksPerSecond = 1ull << exponent;
                } else if (exponent <= 18) { // power of ten, must fit in 64 bits
                    uint64_t t = 1;
                    for (unsigned i = 0; i < exponent; ++i) t *= 10;
                    iface.ticksPerSecond = t;
                }
            }
            if (padded > size - off) break;
            off += padded;
        }
    }
} // namespace

/// PCAP FILE PROCESSING

bool core::FileProcessor::processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                          std::string &message, LoadControl *control) {
    message.clear();
    captureStart_ = 0;
    std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
    if (!file.is_open()) {
        message = "Failed to open file: " + filepath;
        return false;
    }
    const uint64_t fileSize = fileSizeOf(file);
    if (control) control->totalBytes = fileSize;

    uint8_t gh[24];
    if (!file.read(reinterpret_cast<char *>(gh), sizeof(gh))) {
        message = "File is too short to be a PCAP file";
        return false;
    }

    // The magic number tells both the byte order and the timestamp precision of the file.
    Endian e;
    uint32_t magic;
    std::memcpy(&magic, gh, sizeof(magic));
    uint64_t fractionsPerSecond = 1000000;
    if (magic == kPcapMagicMicro || magic == kPcapMagicNano) {
        e.swap = false;
    } else if (magic == swap32(kPcapMagicMicro) || magic == swap32(kPcapMagicNano)) {
        e.swap = true;
    } else {
        message = "Incompatible PCAP file format";
        return false;
    }
    if (e.u32(gh) == kPcapMagicNano) fractionsPerSecond = 1000000000;

    // The low 28 bits of the "network" field are the LINKTYPE (upper bits hold FCS flags).
    const uint32_t linkType = e.u32(gh + 20) & 0x0fffffff;

    TimeBase timeBase;
    const size_t firstPacket = packets.size();

    uint8_t ph[16];
    uint64_t consumed = sizeof(gh);
    while (true) {
        file.read(reinterpret_cast<char *>(ph), sizeof(ph));
        const auto got = file.gcount();
        if (got == 0) break; // clean end of file
        if (got < static_cast<std::streamsize>(sizeof(ph))) {
            message = "Truncated packet header after packet " + std::to_string(packets.size() - firstPacket);
            break;
        }

        const uint32_t tsSec = e.u32(ph);
        const uint32_t tsFrac = e.u32(ph + 4);
        const uint32_t inclLen = e.u32(ph + 8);
        const uint32_t origLen = e.u32(ph + 12);
        if (inclLen > kMaxRecordSize || inclLen > remainingBytes(file, fileSize)) {
            message = "Truncated or corrupt packet " + std::to_string(packets.size() - firstPacket + 1);
            break;
        }

        std::vector<char> data(inclLen);
        if (inclLen > 0 && !file.read(data.data(), inclLen)) {
            message = "Failed to read packet " + std::to_string(packets.size() - firstPacket + 1);
            break;
        }

        const uint64_t dataOffset = consumed + sizeof(ph);
        consumed = dataOffset + inclLen;
        addPacket(parser, packets, timeBase.relative(tsSec, tsFrac, fractionsPerSecond), linkType, dataOffset, origLen, data);
        if (reportProgress(control, consumed, packets.size() - firstPacket)) {
            message = "Cancelled";
            return false;
        }
    }
    captureStart_ = timeBase.startEpoch();
    reportProgress(control, fileSize, packets.size() - firstPacket);

    return true;
}

/// PCAPNG FILE PROCESSING

bool core::FileProcessor::processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                            std::string &message, LoadControl *control) {
    message.clear();
    captureStart_ = 0;
    std::ifstream file(pathFromUtf8(filepath), std::ios::binary);
    if (!file.is_open()) {
        message = "Failed to open file: " + filepath;
        return false;
    }
    const uint64_t fileSize = fileSizeOf(file);
    if (control) control->totalBytes = fileSize;

    Endian e;
    bool haveSection = false;
    std::vector<Interface> interfaces;
    TimeBase timeBase;
    double lastTime = 0;
    const size_t firstPacket = packets.size();

    // Stops the read loop. Packets that were read before the problem are kept.
    auto fail = [&](const std::string &what) {
        message = what;
        return packets.size() > firstPacket;
    };

    std::vector<uint8_t> block;
    uint64_t consumed = 0;
    while (true) {
        block.assign(8, 0);
        file.read(reinterpret_cast<char *>(block.data()), 8);
        const auto got = file.gcount();
        if (got == 0) break; // clean end of file
        if (got < 8) return fail("Truncated block header");

        uint32_t type;
        std::memcpy(&type, block.data(), sizeof(type)); // SHB type is a palindrome, byte order independent
        size_t have = 8;

        if (type == kBlockSHB) {
            // The byte-order magic right after the header decides how the section is encoded.
            block.resize(12);
            if (!file.read(reinterpret_cast<char *>(block.data() + 8), 4)) return fail("Truncated Section Header Block");
            have = 12;
            uint32_t magic;
            std::memcpy(&magic, block.data() + 8, sizeof(magic));
            if (magic == kByteOrderMagic) e.swap = false;
            else if (magic == swap32(kByteOrderMagic)) e.swap = true;
            else return fail("Invalid pcapng byte-order magic");
            haveSection = true;
            interfaces.clear();
        } else if (!haveSection) {
            message = "Not a pcapng file (missing Section Header Block)";
            return false;
        } else {
            type = e.u32(block.data());
        }

        const uint32_t totalLength = e.u32(block.data() + 4);
        if (totalLength < 12 || totalLength % 4 != 0 || totalLength > kMaxRecordSize || totalLength < have) {
            return fail("Invalid block length " + std::to_string(totalLength));
        }
        if (totalLength - have > remainingBytes(file, fileSize)) return fail("Truncated block");

        block.resize(totalLength);
        if (totalLength > have &&
            !file.read(reinterpret_cast<char *>(block.data() + have), totalLength - have)) {
            return fail("Failed to read block");
        }
        if (e.u32(block.data() + totalLength - 4) != totalLength) {
            return fail("Mismatched block length at end of block. Expected: " + std::to_string(totalLength));
        }

        const uint64_t blockStart = consumed;
        consumed += totalLength;
        if (reportProgress(control, consumed, packets.size() - firstPacket)) {
            message = "Cancelled";
            return false;
        }

        const uint8_t *body = block.data() + 8;
        const size_t bodySize = totalLength - 12;

        switch (type) {
            case kBlockSHB:
                if (bodySize < 16) return fail("Section Header Block too short");
                break;
            case kBlockIDB: {
                if (bodySize < 8) return fail("Interface Description Block too short");
                Interface iface;
                iface.linkType = e.u16(body);
                iface.snapLen = e.u32(body + 4);
                parseIdbOptions(e, body + 8, bodySize - 8, iface);
                interfaces.push_back(iface);
            } break;
            case kBlockEPB: {
                if (bodySize < 20) return fail("Enhanced Packet Block too short");
                const uint32_t interfaceId = e.u32(body);
                const uint64_t ticks = (static_cast<uint64_t>(e.u32(body + 4)) << 32) | e.u32(body + 8);
                const uint32_t capturedLength = e.u32(body + 12);
                if (capturedLength > bodySize - 20) return fail("Enhanced Packet Block has invalid captured length");

                const uint64_t tps = interfaceId < interfaces.size()
                                         ? interfaces[interfaceId].ticksPerSecond
                                         : kDefaultTicksPerSecond;
                lastTime = timeBase.relative(ticks / tps, ticks % tps, tps);
                const uint32_t linkType = interfaceId < interfaces.size() ? interfaces[interfaceId].linkType : 1;

                // Only captured_length bytes are packet data; the rest is padding and options.
                const char *data = reinterpret_cast<const char *>(body + 20);
                addPacket(parser, packets, lastTime, linkType, blockStart + 8 + 20, e.u32(body + 16),
                          std::vector<char>(data, data + capturedLength));
            } break;
            case kBlockSPB: {
                if (bodySize < 4) return fail("Simple Packet Block too short");
                const uint32_t originalLength = e.u32(body);
                size_t captured = std::min<size_t>(originalLength, bodySize - 4);
                if (!interfaces.empty() && interfaces[0].snapLen > 0) {
                    captured = std::min<size_t>(captured, interfaces[0].snapLen);
                }
                // SPBs carry no timestamp; reuse the previous packet's time.
                const char *data = reinterpret_cast<const char *>(body + 4);
                addPacket(parser, packets, lastTime, interfaces.empty() ? 1 : interfaces[0].linkType, blockStart + 8 + 4,
                          originalLength, std::vector<char>(data, data + captured));
            } break;
            default:
                break; // NRB, ISB, custom and unknown blocks carry nothing we display
        }
    }

    if (!haveSection) {
        message = "Not a pcapng file";
        return false;
    }
    captureStart_ = timeBase.startEpoch();
    reportProgress(control, fileSize, packets.size() - firstPacket);
    return true;
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
    bool readFragment(const std::vector<char> &frame, const packet::PacketInfo &p, network::IpFragment &out) {
        const size_t ip = p.l2_size;
        if (frame.size() < ip + 20) return false;
        const auto u8 = [&](size_t i) { return static_cast<uint8_t>(frame[ip + i]); };
        const size_t ihl = static_cast<size_t>(u8(0) & 0x0F) * 4;
        const size_t total = (static_cast<size_t>(u8(2)) << 8) | u8(3);
        const uint16_t field = static_cast<uint16_t>((u8(6) << 8) | u8(7));
        if (ihl < 20 || total < ihl || frame.size() < ip + ihl) return false;
        const size_t end = std::min(frame.size(), ip + total);
        out.offset = (field & 0x1FFF) * 8u;
        out.moreFragments = (field & 0x2000) != 0;
        out.packetNumber = static_cast<uint32_t>(p.number);
        out.data.assign(frame.begin() + static_cast<std::ptrdiff_t>(ip + ihl), frame.begin() + static_cast<std::ptrdiff_t>(end));
        return true;
    }
} // namespace

bool core::buildPacketDetails(const std::string &filepath, const packet::PacketInfo &summary, packet::PacketInfo &details,
                              const std::vector<packet::PacketInfo> *allPackets) {
    std::vector<char> bytes;
    if (!readPacketBytes(filepath, summary, bytes)) return false;

    details = summary;
    packet::PacketParser parser; // fresh parser: TCP numbers come from `summary` (Replay mode)

    // the last fragment of a datagram needs the earlier ones to show the reassembled protocols
    std::vector<char> reassembled;
    std::vector<uint32_t> fragmentNumbers;
    if (summary.ip_frag == 2 && allPackets) {
        CaptureReader reader(filepath);
        std::vector<network::IpFragment> fragments;
        std::vector<char> frame;
        for (const auto &p: *allPackets) {
            if (p.ip_version != 4 || p.ip_frag == 0 || p.ip_id != summary.ip_id || p.ip_protocol != summary.ip_protocol ||
                p.source != summary.source || p.destination != summary.destination) continue;
            network::IpFragment f;
            if (reader.read(p, frame) && readFragment(frame, p, f)) fragments.push_back(std::move(f));
        }
        if (network::assembleIpv4Payload(fragments, reassembled)) {
            for (const auto &f: fragments) fragmentNumbers.push_back(f.packetNumber);
            std::sort(fragmentNumbers.begin(), fragmentNumbers.end());
            fragmentNumbers.erase(std::unique(fragmentNumbers.begin(), fragmentNumbers.end()), fragmentNumbers.end());
            parser.setReassembly(&reassembled, &fragmentNumbers);
        }
    }

    parser.parsePacket(details, bytes, dissect::ParseMode::Replay);
    details.raw_data = std::move(bytes);
    return true;
}

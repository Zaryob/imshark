#include <core.h>

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

    /// Reports time relative to the first packet that was seen.
    struct TimeBase {
        bool set = false;
        long double base = 0;

        double relative(long double absolute) {
            if (!set) {
                set = true;
                base = absolute;
            }
            return static_cast<double>(absolute - base);
        }
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

    void addPacket(packet::PacketParser &parser, std::vector<packet::PacketInfo> &packets,
                   double time, uint32_t linkType, std::vector<char> data) {
        packet::PacketInfo pack(static_cast<int>(packets.size()) + 1);
        pack.time = time;
        pack.link_type = linkType;
        parser.parsePacket(pack, data);
        pack.raw_data = std::move(data);
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
                                          std::string &message) {
    message.clear();
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        message = "Failed to open file: " + filepath;
        return false;
    }
    const uint64_t fileSize = fileSizeOf(file);

    uint8_t gh[24];
    if (!file.read(reinterpret_cast<char *>(gh), sizeof(gh))) {
        message = "File is too short to be a PCAP file";
        return false;
    }

    // The magic number tells both the byte order and the timestamp precision of the file.
    Endian e;
    uint32_t magic;
    std::memcpy(&magic, gh, sizeof(magic));
    double fractionsPerSecond = 1e6;
    if (magic == kPcapMagicMicro || magic == kPcapMagicNano) {
        e.swap = false;
    } else if (magic == swap32(kPcapMagicMicro) || magic == swap32(kPcapMagicNano)) {
        e.swap = true;
    } else {
        message = "Incompatible PCAP file format";
        return false;
    }
    if (e.u32(gh) == kPcapMagicNano) fractionsPerSecond = 1e9;

    // The low 28 bits of the "network" field are the LINKTYPE (upper bits hold FCS flags).
    const uint32_t linkType = e.u32(gh + 20) & 0x0fffffff;

    TimeBase timeBase;
    const size_t firstPacket = packets.size();

    uint8_t ph[16];
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
        if (inclLen > kMaxRecordSize || inclLen > remainingBytes(file, fileSize)) {
            message = "Truncated or corrupt packet " + std::to_string(packets.size() - firstPacket + 1);
            break;
        }

        std::vector<char> data(inclLen);
        if (inclLen > 0 && !file.read(data.data(), inclLen)) {
            message = "Failed to read packet " + std::to_string(packets.size() - firstPacket + 1);
            break;
        }

        const long double absolute = static_cast<long double>(tsSec) + tsFrac / fractionsPerSecond;
        addPacket(parser, packets, timeBase.relative(absolute), linkType, std::move(data));
    }

    return true;
}

/// PCAPNG FILE PROCESSING

bool core::FileProcessor::processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                                            std::string &message) {
    message.clear();
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        message = "Failed to open file: " + filepath;
        return false;
    }
    const uint64_t fileSize = fileSizeOf(file);

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
                lastTime = timeBase.relative(static_cast<long double>(ticks) / tps);
                const uint32_t linkType = interfaceId < interfaces.size() ? interfaces[interfaceId].linkType : 1;

                // Only captured_length bytes are packet data; the rest is padding and options.
                const char *data = reinterpret_cast<const char *>(body + 20);
                addPacket(parser, packets, lastTime, linkType, std::vector<char>(data, data + capturedLength));
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
                addPacket(parser, packets, lastTime, interfaces.empty() ? 1 : interfaces[0].linkType,
                          std::vector<char>(data, data + captured));
            } break;
            default:
                break; // NRB, ISB, custom and unknown blocks carry nothing we display
        }
    }

    if (!haveSection) {
        message = "Not a pcapng file";
        return false;
    }
    return true;
}

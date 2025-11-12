#include <core.h>

#include <capture_reader.h>
#include <network/byteorder.h>

#include <algorithm>
#include <exception>
#include <bit>
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
    constexpr uint32_t kBlockPB  = 0x00000002; // (obsolete) Packet Block
    constexpr uint32_t kBlockSPB = 0x00000003; // Simple Packet Block
    constexpr uint32_t kBlockNRB = 0x00000004; // Name Resolution Block
    constexpr uint32_t kBlockISB = 0x00000005; // Interface Statistics Block
    constexpr uint32_t kBlockEPB = 0x00000006; // Enhanced Packet Block
    constexpr uint32_t kBlockDSB = 0x0000000A; // Decryption Secrets Block
    constexpr size_t kMaxStoredSecrets = 32u << 20; // bytes of Decryption Secrets Blocks kept in the capture info
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

    struct Interface {
        uint32_t linkType = 1; // LINKTYPE_ETHERNET
        uint32_t snapLen = 0;
        uint64_t ticksPerSecond = kDefaultTicksPerSecond;
        std::string name, description;
        uint8_t fcsLength = 0; // FCS bytes per frame (pcap network field / pcapng if_fcslen)
        int64_t tsOffset = 0;  // if_tsoffset: seconds to add to the timestamps of this interface
    };

    // 64-bit option values are stored as two 32-bit words in the file's byte order (high word first if big endian)
    uint64_t read64(const Endian &e, const uint8_t *v, bool bigEndian) {
        const uint32_t first = e.u32(v), second = e.u32(v + 4);
        return bigEndian ? (static_cast<uint64_t>(first) << 32) | second : (static_cast<uint64_t>(second) << 32) | first;
    }

    // true if the multi-byte integers of the file are big endian (Endian::swap says "differs from this machine")
    bool fileBigEndian(const Endian &e) { return (std::endian::native == std::endian::little) == e.swap; }

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
        packets.emplace_back(std::move(pack));
    }

    /// Calls `f(code, value, length)` for every option in [p, p + size) (pcapng option format).
    template<typename F>
    void forEachOption(const Endian &e, const uint8_t *p, size_t size, F &&f) {
        size_t off = 0;
        while (size - off >= 4) {
            const uint16_t code = e.u16(p + off);
            const uint16_t len = e.u16(p + off + 2);
            off += 4;
            if (code == kOptEnd) break;
            if (len > size - off) break; // option runs past the block
            f(code, p + off, static_cast<size_t>(len));
            const size_t padded = (static_cast<size_t>(len) + 3) & ~static_cast<size_t>(3);
            if (padded > size - off) break;
            off += padded;
        }
    }

    std::string optionText(const uint8_t *v, size_t len) { return std::string(reinterpret_cast<const char *>(v), std::min<size_t>(len, 4096)); }

    /// Parses the options of an Interface Description Block (if_name, if_description, if_tsresol, if_fcslen).
    void parseIdbOptions(const Endian &e, const uint8_t *p, size_t size, Interface &iface) {
        forEachOption(e, p, size, [&](uint16_t code, const uint8_t *v, size_t len) {
            if (code == 2) iface.name = optionText(v, len);
            else if (code == 3) iface.description = optionText(v, len);
            else if (code == kOptIfTsResol && len == 1) {
                const unsigned exponent = v[0] & 0x7f;
                if (v[0] & 0x80) { // power of two
                    if (exponent <= 62) iface.ticksPerSecond = 1ull << exponent;
                } else if (exponent <= 18) { // power of ten, must fit in 64 bits
                    uint64_t t = 1;
                    for (unsigned i = 0; i < exponent; ++i) t *= 10;
                    iface.ticksPerSecond = t;
                }
            } else if (code == 14 && len == 8) { // if_tsoffset: signed seconds added to every timestamp
                iface.tsOffset = static_cast<int64_t>(read64(e, v, fileBigEndian(e)));
            } else if (code == 13 && len == 1) {
                // if_fcslen is the length of the FCS in BITS (pcapng spec: 32 for an Ethernet CRC). Values below 8 cannot
                // be a bit count, so they are read leniently as bytes (some writers store the byte count).
                iface.fcsLength = v[0] >= 8 ? static_cast<uint8_t>(v[0] / 8) : v[0];
            }
        });
    }
} // namespace

/// PCAP FILE PROCESSING

bool core::FileProcessor::processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
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

    // The low 16 bits of the "network" field are the LINKTYPE; bits 28..31 carry the FCS length
    // when the FCS-present flag (bit 29) is set.
    const uint32_t rawLinkType = e.u32(gh + 20);
    const uint32_t linkType = rawLinkType & 0xFFFF;
    // Bits 28..31: bit 28 says that an FCS length is given, bits 29..31 hold it in units of 16 bits
    // (pcap savefile format). 0x50000001 therefore means "Ethernet, 4 FCS bytes"; without bit 28 nothing is known.
    const uint8_t fcsLen = (rawLinkType & 0x10000000u) ? static_cast<uint8_t>(((rawLinkType >> 29) & 0x7) * 2) : 0;

    info_ = CaptureInfo();
    info_.fileSize = fileSize;
    info_.format = std::string("pcap (") + (e.swap ? "big" : "little") + " endian, " + (fractionsPerSecond == 1000000000 ? "nanosecond" : "microsecond") +
                   " timestamps), version " + std::to_string(e.u16(gh + 4)) + "." + std::to_string(e.u16(gh + 6));
    {
        InterfaceInfo itf;
        itf.linkType = linkType;
        itf.snapLen = e.u32(gh + 16);
        itf.ticksPerSecond = fractionsPerSecond;
        itf.fcsLength = fcsLen;
        info_.interfaces.push_back(itf);
    }

    TimeBase timeBase;
    const size_t firstPacket = packets.size();
    reservePackets(packets, fileSize, 16 + 28);

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
        addPacket(parser, packets, timeBase.relative(tsSec, tsFrac, fractionsPerSecond), linkType, dataOffset, origLen, data, false, fcsLen);
        info_.interfaces[0].packets++;
        if (reportProgress(control, consumed, packets.size() - firstPacket)) {
            message = "Cancelled";
            return false;
        }
    }
    captureStart_ = timeBase.startEpoch();
    reportProgress(control, fileSize, packets.size() - firstPacket);
    parser.sessions().freeze();

    return true;
}

/// PCAPNG FILE PROCESSING

bool core::FileProcessor::processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
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

    info_ = CaptureInfo();
    info_.fileSize = fileSize;
    info_.format = "pcapng";

    Endian e;
    bool haveSection = false;
    std::vector<Interface> interfaces;
    // Packets may name an interface that no Interface Description Block defined. They are kept (not guessed to be
    // Ethernet) with an "undefined link type" and the problem is reported once at the end.
    size_t undefinedInterfaceRefs = 0;
    uint32_t firstUndefinedInterface = 0;
    auto interfaceFor = [&](uint32_t id) -> const Interface * {
        if (id < interfaces.size()) return &interfaces[id];
        if (undefinedInterfaceRefs++ == 0) firstUndefinedInterface = id;
        return nullptr;
    };
    size_t storedSecretsBytes = 0; // size of the Decryption Secrets Blocks kept in info_
    size_t sectionBase = 0; // index of the section's first interface in info_.interfaces
    TimeBase timeBase;
    double lastTime = 0;
    const size_t firstPacket = packets.size();
    reservePackets(packets, fileSize, 32 + 28);

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
            case kBlockSHB: {
                if (bodySize < 16) return fail("Section Header Block too short");
                ++info_.sections;
                sectionBase = info_.interfaces.size(); // interface ids of this section start here
                if (info_.sections == 1) {
                    info_.format = std::string("pcapng (") + (fileBigEndian(e) ? "big" : "little") + " endian), version " +
                                   std::to_string(e.u16(body + 4)) + "." + std::to_string(e.u16(body + 6));
                    forEachOption(e, body + 16, bodySize - 16, [&](uint16_t code, const uint8_t *v, size_t len) {
                        if (code == 1) info_.comment = optionText(v, len);
                        else if (code == 2) info_.hardware = optionText(v, len);
                        else if (code == 3) info_.os = optionText(v, len);
                        else if (code == 4) info_.application = optionText(v, len);
                    });
                }
            } break;
            case kBlockIDB: {
                if (bodySize < 8) return fail("Interface Description Block too short");
                Interface iface;
                iface.linkType = e.u16(body);
                iface.snapLen = e.u32(body + 4);
                parseIdbOptions(e, body + 8, bodySize - 8, iface);
                interfaces.push_back(iface);
                InterfaceInfo itf;
                itf.linkType = iface.linkType;
                itf.snapLen = iface.snapLen;
                itf.ticksPerSecond = iface.ticksPerSecond;
                itf.name = iface.name;
                itf.description = iface.description;
                itf.fcsLength = iface.fcsLength;
                info_.interfaces.push_back(itf);
            } break;
            case kBlockEPB: {
                if (bodySize < 20) return fail("Enhanced Packet Block too short");
                const uint32_t interfaceId = e.u32(body);
                const uint64_t ticks = (static_cast<uint64_t>(e.u32(body + 4)) << 32) | e.u32(body + 8);
                const uint32_t capturedLength = e.u32(body + 12);
                if (capturedLength > bodySize - 20) return fail("Enhanced Packet Block has invalid captured length");

                const Interface *itf = interfaceFor(interfaceId);
                const uint64_t tps = itf ? itf->ticksPerSecond : kDefaultTicksPerSecond;
                lastTime = timeBase.relative(ticks / tps + static_cast<uint64_t>(itf ? itf->tsOffset : 0), ticks % tps, tps);
                const uint32_t linkType = itf ? itf->linkType : packet::kUndefinedLinkType;
                const uint8_t epbFcs = itf ? itf->fcsLength : 0;

                // Only captured_length bytes are packet data; the rest is padding and options.
                const char *data = reinterpret_cast<const char *>(body + 20);
                bool hasComment = false;
                const size_t optionsAt = 20 + ((static_cast<size_t>(capturedLength) + 3) & ~static_cast<size_t>(3));
                if (optionsAt < bodySize) {
                    forEachOption(e, body + optionsAt, bodySize - optionsAt, [&](uint16_t code, const uint8_t *v, size_t len) {
                        if (code == 1 && len > 0) {
                            info_.packetComments[static_cast<uint32_t>(packets.size()) + 1] = optionText(v, len);
                            hasComment = true;
                        }
                    });
                }
                if (sectionBase + interfaceId < info_.interfaces.size()) info_.interfaces[sectionBase + interfaceId].packets++;
                addPacket(parser, packets, lastTime, linkType, blockStart + 8 + 20, e.u32(body + 16),
                          std::vector<char>(data, data + capturedLength), hasComment, epbFcs);
            } break;
            case kBlockPB: { // obsolete Packet Block: 2-byte iface id, 2-byte drops, 8-byte ts, captured, original, data
                if (bodySize < 20) return fail("Packet Block too short");
                const uint32_t interfaceId = e.u16(body);
                const uint64_t ticks = (static_cast<uint64_t>(e.u32(body + 4)) << 32) | e.u32(body + 8);
                const uint32_t capturedLength = e.u32(body + 12);
                if (capturedLength > bodySize - 20) return fail("Packet Block has invalid captured length");

                const Interface *itf = interfaceFor(interfaceId);
                const uint64_t tps = itf ? itf->ticksPerSecond : kDefaultTicksPerSecond;
                lastTime = timeBase.relative(ticks / tps + static_cast<uint64_t>(itf ? itf->tsOffset : 0), ticks % tps, tps);
                const uint32_t linkType = itf ? itf->linkType : packet::kUndefinedLinkType;
                const uint8_t pbFcs = itf ? itf->fcsLength : 0;
                const char *data = reinterpret_cast<const char *>(body + 20);

                bool hasComment = false;
                const size_t optionsAt = 20 + ((static_cast<size_t>(capturedLength) + 3) & ~static_cast<size_t>(3));
                if (optionsAt < bodySize) {
                    forEachOption(e, body + optionsAt, bodySize - optionsAt, [&](uint16_t code, const uint8_t *v, size_t len) {
                        if (code == 1 && len > 0) {
                            info_.packetComments[static_cast<uint32_t>(packets.size()) + 1] = optionText(v, len);
                            hasComment = true;
                        }
                    });
                }
                if (sectionBase + interfaceId < info_.interfaces.size()) info_.interfaces[sectionBase + interfaceId].packets++;
                addPacket(parser, packets, lastTime, linkType, blockStart + 8 + 20, e.u32(body + 16),
                          std::vector<char>(data, data + capturedLength), hasComment, pbFcs);
            } break;
            case kBlockSPB: {
                if (bodySize < 4) return fail("Simple Packet Block too short");
                const uint32_t originalLength = e.u32(body);
                size_t captured = std::min<size_t>(originalLength, bodySize - 4);
                if (!interfaces.empty() && interfaces[0].snapLen > 0) {
                    captured = std::min<size_t>(captured, interfaces[0].snapLen);
                }
                if (sectionBase < info_.interfaces.size()) info_.interfaces[sectionBase].packets++;
                // SPBs carry no timestamp; reuse the previous packet's time.
                const char *data = reinterpret_cast<const char *>(body + 4);
                const Interface *itf = interfaceFor(0);   // an SPB always belongs to the first interface
                const uint8_t spbFcs = itf ? itf->fcsLength : 0;
                addPacket(parser, packets, lastTime, itf ? itf->linkType : packet::kUndefinedLinkType, blockStart + 8 + 4,
                          originalLength, std::vector<char>(data, data + captured), false, spbFcs);
            } break;
            case kBlockNRB: { // name resolution records: type, length, value (padded to 4)
                size_t off = 0;
                while (bodySize - off >= 4 && info_.names.size() < 10000) {
                    const uint16_t recType = e.u16(body + off), recLen = e.u16(body + off + 2);
                    off += 4;
                    if (recType == 0 || recLen > bodySize - off) break;
                    const uint8_t *v = body + off;
                    const size_t addrLen = recType == 1 ? 4 : recType == 2 ? 16 : 0;
                    if (addrLen > 0 && recLen > addrLen) {
                        const std::string address = recType == 1 ? network::formatIPv4(v) : network::formatIPv6(v);
                        size_t i = addrLen;
                        while (i < recLen) { // one or more zero terminated names
                            size_t j = i;
                            while (j < recLen && v[j] != 0) ++j;
                            if (j > i) info_.names.push_back({address, std::string(reinterpret_cast<const char *>(v + i), j - i)});
                            i = j + 1;
                        }
                    }
                    off += (static_cast<size_t>(recLen) + 3) & ~static_cast<size_t>(3);
                    if (off > bodySize) break;
                }
            } break;
            case kBlockISB: { // interface id, timestamp, options (comment, ifrecv, ifdrop)
                if (bodySize < 12) break;
                const uint32_t id = e.u32(body);
                if (sectionBase + id >= info_.interfaces.size()) break;
                auto &itf = info_.interfaces[sectionBase + id];
                forEachOption(e, body + 12, bodySize - 12, [&](uint16_t code, const uint8_t *v, size_t len) {
                    if ((code == 4 || code == 5) && len == 8) {
                        const uint64_t value = read64(e, v, fileBigEndian(e));
                        itf.hasStats = true;
                        (code == 4 ? itf.received : itf.dropped) = value;
                    }
                });
            } break;
            case kBlockDSB: { // secrets type, secrets length, secrets (padded to 4), options
                if (bodySize < 8) break;
                const uint32_t secretsType = e.u32(body), secretsLength = e.u32(body + 4);
                if (secretsLength > bodySize - 8) break;
                std::string data(reinterpret_cast<const char *>(body + 8), secretsLength);
                if (secretsType == core::kSecretsTypeTlsKeyLog) {
                    const tls::KeyLogStats stats = parser.sessions().tlsCaptureKeys().parseText(data);
                    info_.tlsKeyLogSecrets += stats.accepted;
                    info_.tlsKeyLogMalformed += stats.malformed;
                }
                if (storedSecretsBytes + data.size() <= kMaxStoredSecrets) {
                    storedSecretsBytes += data.size();
                    info_.decryptionSecrets.push_back({secretsType, std::move(data)});
                }
            } break;
            default:
                break; // custom and unknown blocks carry nothing we display
        }
    }

    if (!haveSection) {
        message = "Not a pcapng file";
        return false;
    }
    captureStart_ = timeBase.startEpoch();
    reportProgress(control, fileSize, packets.size() - firstPacket);
    parser.sessions().freeze();
    if (undefinedInterfaceRefs > 0 && message.empty()) {
        message = std::to_string(undefinedInterfaceRefs) + " packet(s) refer to interface " + std::to_string(firstUndefinedInterface) +
                  ", which no Interface Description Block defines; they are shown without protocol decoding";
    }
    return true;
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

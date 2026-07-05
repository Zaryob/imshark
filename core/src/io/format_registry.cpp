#include <io/format_registry.h>

#include <cstring>

#include <io/reader_util.h>

namespace {
    using namespace core::io;

    bool matchPcap(const uint8_t *buf, size_t len) {
        if (len < 4) return false;
        uint32_t magic;
        std::memcpy(&magic, buf, 4);
        return magic == kPcapMagicMicro || magic == kPcapMagicNano || magic == swap32(kPcapMagicMicro) || magic == swap32(kPcapMagicNano);
    }

    bool matchPcapng(const uint8_t *buf, size_t len) {
        if (len < 4) return false;
        uint32_t magic;
        std::memcpy(&magic, buf, 4);
        return magic == kBlockSHB;
    }

    // gzip (RFC 1952): 1f 8b, method 8 (deflate), no reserved flag bits. Must be probed before ERF, whose heuristic
    // would otherwise take a gzip header with a plausible length field for a record.
    bool matchGzip(const uint8_t *buf, size_t len) { return len >= 4 && buf[0] == 0x1f && buf[1] == 0x8b && buf[2] == 8 && (buf[3] & 0xE0) == 0; }

    // Microsoft Network Monitor: "GMBU" (0x55424d47 in big endian)
    bool matchNetMon(const uint8_t *buf, size_t len) { return len >= 4 && std::memcmp(buf, "GMBU", 4) == 0; }

    // Sun snoop: "snoop\0\0\0"
    bool matchSnoop(const uint8_t *buf, size_t len) { return len >= 8 && std::memcmp(buf, "snoop\0\0\0", 8) == 0; }

    // AIX iptrace: "iptrace 1.0" or "iptrace 2.0"
    bool matchIptrace(const uint8_t *buf, size_t len) {
        return len >= 11 && (std::memcmp(buf, "iptrace 1.0", 11) == 0 || std::memcmp(buf, "iptrace 2.0", 11) == 0);
    }

    // Endace ERF has no file header: the first record starts at offset 0 and is
    //   uint64_t timestamp; uint8_t type; uint8_t flags; uint16_t rlen; uint16_t lctr; uint16_t wlen   (big endian, 16 bytes)
    // Accepted when the type (bit 7 is the extension header flag) is one of the known 1..27, the record length covers
    // the header and the wire length does not exceed it (unless the truncated flag, bit 3 of the flags byte, says the
    // record holds only the start of a longer frame). Type 0 (legacy) is not claimed. Being a heuristic it comes last.
    bool matchErf(const uint8_t *buf, size_t len) {
        if (len < 16) return false;
        const uint8_t erfType = buf[8] & 0x7F;
        uint16_t rlen, wlen;
        std::memcpy(&rlen, buf + 10, 2);
        std::memcpy(&wlen, buf + 14, 2);
        rlen = swap16(rlen);
        wlen = swap16(wlen);
        return erfType >= 1 && erfType <= 27 && rlen >= 16 && (wlen <= rlen || (buf[9] & 0x08) != 0);
    }
} // namespace

const std::vector<core::io::FormatDescriptor> &core::io::captureFormats() {
    static const std::vector<FormatDescriptor> formats = {
        {FileFormat::Pcap, "PCAP", matchPcap, makePcapReader, false},
        {FileFormat::Pcapng, "PCAPNG", matchPcapng, makePcapngReader, false},
        {FileFormat::Gzip, "gzip", matchGzip, nullptr, true},
        {FileFormat::NetMon, "Microsoft Network Monitor", matchNetMon, makeNetMonReader, false},
        {FileFormat::Snoop, "Sun snoop", matchSnoop, makeSnoopReader, false},
        {FileFormat::Iptrace, "AIX iptrace", matchIptrace, makeIptraceReader, false},
        {FileFormat::Erf, "Endace ERF", matchErf, makeErfReader, false},
    };
    return formats;
}

const core::io::FormatDescriptor *core::io::findFormat(FileFormat format) {
    for (const auto &f: captureFormats()) if (f.format == format) return &f;
    return nullptr;
}

core::FileFormat core::io::identifyFormat(const uint8_t *buf, size_t len) {
    for (const auto &f: captureFormats()) if (f.matches(buf, len)) return f.format;
    return FileFormat::Unknown;
}

std::unique_ptr<core::io::CaptureFileReader> core::io::makeReader(FileFormat format) {
    const FormatDescriptor *f = findFormat(format);
    return f && f->makeReader ? f->makeReader() : nullptr;
}

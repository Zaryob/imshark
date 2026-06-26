// pcapng (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-03.html): a sequence of blocks, each with a type,
// a total length at both ends and a body. Packets live in Enhanced / Simple / (obsolete) Packet Blocks; the other
// blocks carry interfaces, names, statistics and decryption secrets and are folded into the capture info as they pass.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <bit>
#include <istream>

#include <network/byteorder.h>

namespace {
    using namespace core::io;

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

    class PcapngReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &) override {
            in_ = &in;
            fileSize_ = ctx.fileSize;
            info_ = &ctx.info;
            sessions_ = &ctx.sessions;
            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = "pcapng";
            return true; // the section header block is the first thing next() reads
        }

        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            while (true) {
                block_.assign(8, 0);
                in_->read(reinterpret_cast<char *>(block_.data()), 8);
                const auto got = in_->gcount();
                if (got == 0) { // clean end of file
                    if (!haveSection_) return error(issue, "Not a pcapng file");
                    return Status::End;
                }
                if (got < 8) return error(issue, "Truncated block header");

                uint32_t type;
                std::memcpy(&type, block_.data(), sizeof(type)); // SHB type is a palindrome, byte order independent
                size_t have = 8;

                if (type == kBlockSHB) {
                    // The byte-order magic right after the header decides how the section is encoded.
                    block_.resize(12);
                    if (!in_->read(reinterpret_cast<char *>(block_.data() + 8), 4)) return error(issue, "Truncated Section Header Block");
                    have = 12;
                    uint32_t magic;
                    std::memcpy(&magic, block_.data() + 8, sizeof(magic));
                    if (magic == kByteOrderMagic) e_.swap = false;
                    else if (magic == swap32(kByteOrderMagic)) e_.swap = true;
                    else return error(issue, "Invalid pcapng byte-order magic");
                    haveSection_ = true;
                    interfaces_.clear();
                } else if (!haveSection_) {
                    const core::FileFormat fmt = identifyFormat(block_.data(), have);
                    const std::string diag = core::unsupportedFormatDiagnostic(fmt);
                    issue.message = diag.empty() ? "Not a pcapng file (missing Section Header Block)" : diag;
                    issue.keepRecords = false;
                    return Status::Error;
                } else {
                    type = e_.u32(block_.data());
                }

                const uint32_t totalLength = e_.u32(block_.data() + 4);
                if (totalLength < 12 || totalLength % 4 != 0 || totalLength > kMaxRecordSize || totalLength < have) {
                    return error(issue, "Invalid block length " + std::to_string(totalLength));
                }
                if (totalLength - have > remainingBytes(*in_, fileSize_)) return error(issue, "Truncated block");

                block_.resize(totalLength);
                if (totalLength > have &&
                    !in_->read(reinterpret_cast<char *>(block_.data() + have), totalLength - have)) {
                    return error(issue, "Failed to read block");
                }
                if (e_.u32(block_.data() + totalLength - 4) != totalLength) {
                    return error(issue, "Mismatched block length at end of block. Expected: " + std::to_string(totalLength));
                }

                const uint64_t blockStart = consumed_;
                consumed_ += totalLength;

                const uint8_t *body = block_.data() + 8;
                const size_t bodySize = totalLength - 12;

                switch (type) {
                    case kBlockSHB: {
                        if (bodySize < 16) return error(issue, "Section Header Block too short");
                        ++info_->sections;
                        sectionBase_ = info_->interfaces.size(); // interface ids of this section start here
                        if (info_->sections == 1) {
                            info_->format = std::string("pcapng (") + (fileBigEndian(e_) ? "big" : "little") + " endian), version " +
                                            std::to_string(e_.u16(body + 4)) + "." + std::to_string(e_.u16(body + 6));
                            forEachOption(e_, body + 16, bodySize - 16, [&](uint16_t code, const uint8_t *v, size_t len) {
                                if (code == 1) info_->comment = optionText(v, len);
                                else if (code == 2) info_->hardware = optionText(v, len);
                                else if (code == 3) info_->os = optionText(v, len);
                                else if (code == 4) info_->application = optionText(v, len);
                            });
                        }
                    } break;
                    case kBlockIDB: {
                        if (bodySize < 8) return error(issue, "Interface Description Block too short");
                        Interface iface;
                        iface.linkType = e_.u16(body);
                        iface.snapLen = e_.u32(body + 4);
                        parseIdbOptions(e_, body + 8, bodySize - 8, iface);
                        interfaces_.push_back(iface);
                        core::InterfaceInfo itf;
                        itf.linkType = iface.linkType;
                        itf.snapLen = iface.snapLen;
                        itf.ticksPerSecond = iface.ticksPerSecond;
                        itf.name = iface.name;
                        itf.description = iface.description;
                        itf.fcsLength = iface.fcsLength;
                        info_->interfaces.push_back(itf);
                    } break;
                    case kBlockEPB:
                    case kBlockPB: {
                        // EPB: 4-byte interface id; obsolete PB: 2-byte interface id and 2-byte drop count. Then the
                        // 8-byte timestamp, captured and original length, the data and the options.
                        const bool enhanced = type == kBlockEPB;
                        if (bodySize < 20) return error(issue, enhanced ? "Enhanced Packet Block too short" : "Packet Block too short");
                        const uint32_t interfaceId = enhanced ? e_.u32(body) : e_.u16(body);
                        const uint64_t ticks = (static_cast<uint64_t>(e_.u32(body + 4)) << 32) | e_.u32(body + 8);
                        const uint32_t capturedLength = e_.u32(body + 12);
                        if (capturedLength > bodySize - 20) {
                            return error(issue, enhanced ? "Enhanced Packet Block has invalid captured length" : "Packet Block has invalid captured length");
                        }

                        const Interface *itf = interfaceFor(interfaceId);
                        const uint64_t tps = itf ? itf->ticksPerSecond : kDefaultTicksPerSecond;
                        rec.hasTimestamp = true;
                        rec.seconds = ticks / tps + static_cast<uint64_t>(itf ? itf->tsOffset : 0);
                        rec.fraction = ticks % tps;
                        rec.ticksPerSecond = tps;
                        rec.linkType = itf ? itf->linkType : packet::kUndefinedLinkType;
                        rec.fcsLength = itf ? itf->fcsLength : 0;

                        // Only captured_length bytes are packet data; the rest is padding and options.
                        const char *data = reinterpret_cast<const char *>(body + 20);
                        rec.comment.clear();
                        const size_t optionsAt = 20 + ((static_cast<size_t>(capturedLength) + 3) & ~static_cast<size_t>(3));
                        if (optionsAt < bodySize) {
                            forEachOption(e_, body + optionsAt, bodySize - optionsAt, [&](uint16_t code, const uint8_t *v, size_t len) {
                                if (code == 1 && len > 0) rec.comment = optionText(v, len);
                            });
                        }
                        rec.interfaceIndex = sectionBase_ + interfaceId < info_->interfaces.size() ? static_cast<int>(sectionBase_ + interfaceId) : -1;
                        rec.fileOffset = blockStart + 8 + 20;
                        rec.originalLength = e_.u32(body + 16);
                        rec.frame.assign(data, data + capturedLength);
                        ++count_;
                        return Status::Record;
                    }
                    case kBlockSPB: {
                        if (bodySize < 4) return error(issue, "Simple Packet Block too short");
                        const uint32_t originalLength = e_.u32(body);
                        size_t captured = std::min<size_t>(originalLength, bodySize - 4);
                        if (!interfaces_.empty() && interfaces_[0].snapLen > 0) {
                            captured = std::min<size_t>(captured, interfaces_[0].snapLen);
                        }
                        // SPBs carry no timestamp; the driver reuses the previous packet's time.
                        const char *data = reinterpret_cast<const char *>(body + 4);
                        const Interface *itf = interfaceFor(0);   // an SPB always belongs to the first interface
                        rec.hasTimestamp = false;
                        rec.linkType = itf ? itf->linkType : packet::kUndefinedLinkType;
                        rec.fcsLength = itf ? itf->fcsLength : 0;
                        rec.interfaceIndex = sectionBase_ < info_->interfaces.size() ? static_cast<int>(sectionBase_) : -1;
                        rec.comment.clear();
                        rec.fileOffset = blockStart + 8 + 4;
                        rec.originalLength = originalLength;
                        rec.frame.assign(data, data + captured);
                        ++count_;
                        return Status::Record;
                    }
                    case kBlockNRB: { // name resolution records: type, length, value (padded to 4)
                        size_t off = 0;
                        while (bodySize - off >= 4 && info_->names.size() < 10000) {
                            const uint16_t recType = e_.u16(body + off), recLen = e_.u16(body + off + 2);
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
                                    if (j > i) info_->names.push_back({address, std::string(reinterpret_cast<const char *>(v + i), j - i)});
                                    i = j + 1;
                                }
                            }
                            off += (static_cast<size_t>(recLen) + 3) & ~static_cast<size_t>(3);
                            if (off > bodySize) break;
                        }
                    } break;
                    case kBlockISB: { // interface id, timestamp, options (comment, ifrecv, ifdrop)
                        if (bodySize < 12) break;
                        const uint32_t id = e_.u32(body);
                        if (sectionBase_ + id >= info_->interfaces.size()) break;
                        auto &itf = info_->interfaces[sectionBase_ + id];
                        forEachOption(e_, body + 12, bodySize - 12, [&](uint16_t code, const uint8_t *v, size_t len) {
                            if ((code == 4 || code == 5) && len == 8) {
                                const uint64_t value = read64(e_, v, fileBigEndian(e_));
                                itf.hasStats = true;
                                (code == 4 ? itf.received : itf.dropped) = value;
                            }
                        });
                    } break;
                    case kBlockDSB: { // secrets type, secrets length, secrets (padded to 4), options
                        if (bodySize < 8) break;
                        const uint32_t secretsType = e_.u32(body), secretsLength = e_.u32(body + 4);
                        if (secretsLength > bodySize - 8) break;
                        std::string data(reinterpret_cast<const char *>(body + 8), secretsLength);
                        if (secretsType == core::kSecretsTypeTlsKeyLog) {
                            const tls::KeyLogStats stats = sessions_->tlsCaptureKeys().parseText(data);
                            info_->tlsKeyLogSecrets += stats.accepted;
                            info_->tlsKeyLogMalformed += stats.malformed;
                            info_->tlsKeyLogDropped += stats.dropped;
                        }
                        if (storedSecretsBytes_ + data.size() <= kMaxStoredSecrets) {
                            storedSecretsBytes_ += data.size();
                            info_->decryptionSecrets.push_back({secretsType, std::move(data)});
                        }
                    } break;
                    default:
                        break; // custom and unknown blocks carry nothing we display
                }
            }
        }

        uint64_t bytesConsumed() const override { return consumed_; }
        uint64_t minRecordBytes() const override { return 32 + 28; }

        void finish(std::string &message) override {
            if (undefinedInterfaceRefs_ > 0 && message.empty()) {
                message = std::to_string(undefinedInterfaceRefs_) + " packet(s) refer to interface " + std::to_string(firstUndefinedInterface_) +
                          ", which no Interface Description Block defines; they are shown without protocol decoding";
            }
            if (info_->tlsKeyLogDropped > 0) {
                message += (message.empty() ? "" : "; ") + std::to_string(info_->tlsKeyLogDropped) + " TLS secret(s) ignored: key store limit (" +
                           std::to_string(tls::KeyStore::kMaxEntries) + " connections)";
            }
        }

    private:
        // Stops the read. Records that were read before the problem are kept.
        Status error(ReadIssue &issue, const std::string &what) {
            issue.message = what;
            issue.keepRecords = count_ > 0;
            return Status::Error;
        }

        // Packets may name an interface that no Interface Description Block defined. They are kept (not guessed to be
        // Ethernet) with an "undefined link type" and the problem is reported once at the end.
        const Interface *interfaceFor(uint32_t id) {
            if (id < interfaces_.size()) return &interfaces_[id];
            if (undefinedInterfaceRefs_++ == 0) firstUndefinedInterface_ = id;
            return nullptr;
        }

        std::istream *in_ = nullptr;
        core::CaptureInfo *info_ = nullptr;
        dissect::SessionTables *sessions_ = nullptr;
        uint64_t fileSize_ = 0;
        Endian e_;
        bool haveSection_ = false;
        std::vector<Interface> interfaces_;
        size_t undefinedInterfaceRefs_ = 0;
        uint32_t firstUndefinedInterface_ = 0;
        size_t storedSecretsBytes_ = 0; // size of the Decryption Secrets Blocks kept in the capture info
        size_t sectionBase_ = 0;        // index of the section's first interface in info_->interfaces
        std::vector<uint8_t> block_;
        uint64_t consumed_ = 0;
        uint64_t count_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makePcapngReader() { return std::make_unique<PcapngReader>(); }

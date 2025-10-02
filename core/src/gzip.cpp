#include "gzip.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <core.h>

namespace core {
    namespace {
        thread_local uint64_t g_lastOutputSize = 0;

        // ------------------------------------------------------------------------------------------
        struct Failure { std::string message; };  // thrown inside the decoder, caught in gunzipFile
        struct Cancelled {};

        uint32_t crcUpdate(uint32_t crc, const uint8_t *data, size_t n) {
            static const std::array<uint32_t, 256> table = [] {
                std::array<uint32_t, 256> t{};
                for (uint32_t i = 0; i < 256; ++i) {
                    uint32_t c = i;
                    for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                    t[i] = c;
                }
                return t;
            }();
            crc = ~crc;
            for (size_t i = 0; i < n; ++i) crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
            return ~crc;
        }

        // Reads bytes of the compressed file through a buffer; bits are handed out LSB first.
        class Input {
        public:
            Input(std::istream &f, LoadControl *control) : in_(f), control_(control), buf_(1 << 16) {}

            // Next byte without consuming it, or -1 at the end of the file (only valid at a byte boundary).
            int peek() {
                if (pos_ >= end_ && !refill()) return -1;
                return buf_[pos_];
            }

            uint8_t byte() {
                if (pos_ >= end_ && !refill()) throw Failure{"Unexpected end of the compressed data"};
                return buf_[pos_++];
            }

            // `n` bits (0..16)
            unsigned bits(int n) {
                while (count_ < n) {
                    bitbuf_ |= static_cast<uint32_t>(byte()) << count_;
                    count_ += 8;
                }
                const unsigned v = bitbuf_ & ((1u << n) - 1);
                bitbuf_ >>= n;
                count_ -= n;
                return v;
            }

            void alignToByte() { bitbuf_ = 0; count_ = 0; }
            uint64_t consumed() const { return consumed_ + pos_; }

        private:
            bool refill() {
                consumed_ += end_;
                pos_ = end_ = 0;
                in_.read(reinterpret_cast<char *>(buf_.data()), static_cast<std::streamsize>(buf_.size()));
                end_ = static_cast<size_t>(in_.gcount());
                if (control_) {
                    control_->bytesProcessed = consumed_;
                    if (control_->cancelRequested) throw Cancelled{};
                }
                return end_ > 0;
            }

            std::istream &in_;
            LoadControl *control_;
            std::vector<uint8_t> buf_;
            size_t pos_ = 0, end_ = 0;
            uint64_t consumed_ = 0;
            uint32_t bitbuf_ = 0;
            int count_ = 0;
        };

        // Output: written to the file in blocks, the last 32 KiB kept as the back-reference window.
        class Output {
        public:
            explicit Output(std::ostream &f, uint64_t limit = UINT64_MAX) : out_(f), limit_(limit), window_(kWindow), block_() { block_.reserve(1 << 16); }

            void put(uint8_t b) {
                if (total_ >= limit_) throw Failure{"The decompressed data is larger than the allowed size"};
                window_[wpos_] = b;
                wpos_ = (wpos_ + 1) & (kWindow - 1);
                block_.push_back(b);
                ++total_;
                if (block_.size() >= (1u << 16)) flush();
            }

            void copy(unsigned distance, unsigned length) {
                if (distance == 0 || distance > kWindow || distance > total_) throw Failure{"Invalid back-reference in the compressed data"};
                while (length--) put(window_[(wpos_ - distance) & (kWindow - 1)]);
            }

            void flush() {
                if (block_.empty()) return;
                crc_ = crcUpdate(crc_, block_.data(), block_.size());
                out_.write(reinterpret_cast<const char *>(block_.data()), static_cast<std::streamsize>(block_.size()));
                block_.clear();
                if (!out_) throw Failure{"Writing the decompressed file failed (disk full?)"};
            }

            void startMember() { flush(); crc_ = 0; memberStart_ = total_; }
            uint32_t crc() { flush(); return crc_; }
            uint32_t memberSize() const { return static_cast<uint32_t>(total_ - memberStart_); }
            uint64_t total() const { return total_; }

        private:
            static constexpr size_t kWindow = 32768;
            std::ostream &out_;
            uint64_t limit_;
            std::vector<uint8_t> window_;
            std::vector<uint8_t> block_;
            size_t wpos_ = 0;
            uint64_t total_ = 0, memberStart_ = 0;
            uint32_t crc_ = 0;
        };

        // Canonical Huffman code in the style of zlib's "puff": counts per length and symbols in code order.
        struct Huffman {
            std::array<uint16_t, 16> count{};
            std::array<uint16_t, 288> symbol{};
        };

        // Returns the code's "left" value: 0 = complete, > 0 = incomplete, < 0 = over-subscribed.
        int build(Huffman &h, const uint8_t *lengths, int n) {
            h.count.fill(0);
            for (int i = 0; i < n; ++i) h.count[lengths[i]]++;
            if (h.count[0] == n) return 0;                           // no codes: complete (an unused code)
            int left = 1;
            for (int len = 1; len <= 15; ++len) {
                left <<= 1;
                left -= h.count[len];
                if (left < 0) return left;
            }
            std::array<uint16_t, 16> offs{};
            for (int len = 1; len < 15; ++len) offs[len + 1] = static_cast<uint16_t>(offs[len] + h.count[len]);
            for (int i = 0; i < n; ++i) if (lengths[i] != 0) h.symbol[offs[lengths[i]]++] = static_cast<uint16_t>(i);
            return left;
        }

        int decode(Input &in, const Huffman &h) {
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= 15; ++len) {
                code |= static_cast<int>(in.bits(1));
                const int count = h.count[len];
                if (code - count < first) return h.symbol[index + (code - first)];
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            throw Failure{"Invalid Huffman code in the compressed data"};
        }

        const uint16_t kLengthBase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
        const uint8_t kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
        const uint16_t kDistBase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
        const uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

        void inflateCodes(Input &in, Output &out, const Huffman &lit, const Huffman &dist) {
            while (true) {
                int sym = decode(in, lit);
                if (sym < 256) { out.put(static_cast<uint8_t>(sym)); continue; }
                if (sym == 256) return;                              // end of block
                sym -= 257;
                if (sym >= 29) throw Failure{"Invalid length code in the compressed data"};
                const unsigned len = kLengthBase[sym] + in.bits(kLengthExtra[sym]);
                const int ds = decode(in, dist);
                if (ds >= 30) throw Failure{"Invalid distance code in the compressed data"};
                const unsigned d = kDistBase[ds] + in.bits(kDistExtra[ds]);
                out.copy(d, len);
            }
        }

        void inflateStored(Input &in, Output &out) {
            in.alignToByte();
            const unsigned len = in.byte() | (in.byte() << 8);
            const unsigned nlen = in.byte() | (in.byte() << 8);
            if (len != (~nlen & 0xffff)) throw Failure{"Corrupt stored block in the compressed data"};
            for (unsigned i = 0; i < len; ++i) out.put(in.byte());
        }

        void inflateFixed(Input &in, Output &out) {
            static const std::pair<Huffman, Huffman> codes = [] {
                uint8_t lengths[288];
                for (int i = 0; i < 144; ++i) lengths[i] = 8;
                for (int i = 144; i < 256; ++i) lengths[i] = 9;
                for (int i = 256; i < 280; ++i) lengths[i] = 7;
                for (int i = 280; i < 288; ++i) lengths[i] = 8;
                std::pair<Huffman, Huffman> c;
                build(c.first, lengths, 288);
                uint8_t d[30];
                for (auto &x: d) x = 5;
                build(c.second, d, 30);
                return c;
            }();
            inflateCodes(in, out, codes.first, codes.second);
        }

        void inflateDynamic(Input &in, Output &out) {
            const int nlen = static_cast<int>(in.bits(5)) + 257;
            const int ndist = static_cast<int>(in.bits(5)) + 1;
            const int ncode = static_cast<int>(in.bits(4)) + 4;
            if (nlen > 286 || ndist > 30) throw Failure{"Too many length or distance codes in the compressed data"};

            static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            uint8_t lengths[320] = {0};
            for (int i = 0; i < ncode; ++i) lengths[order[i]] = static_cast<uint8_t>(in.bits(3));
            Huffman lengthCode;
            if (build(lengthCode, lengths, 19) != 0) throw Failure{"Incomplete code-length code in the compressed data"};

            int index = 0;
            while (index < nlen + ndist) {
                int sym = decode(in, lengthCode);
                if (sym < 16) { lengths[index++] = static_cast<uint8_t>(sym); continue; }
                int repeat, value = 0;
                if (sym == 16) {
                    if (index == 0) throw Failure{"Repeat with no previous length in the compressed data"};
                    value = lengths[index - 1];
                    repeat = 3 + static_cast<int>(in.bits(2));
                } else if (sym == 17) {
                    repeat = 3 + static_cast<int>(in.bits(3));
                } else {
                    repeat = 11 + static_cast<int>(in.bits(7));
                }
                if (index + repeat > nlen + ndist) throw Failure{"Too many code lengths in the compressed data"};
                while (repeat--) lengths[index++] = static_cast<uint8_t>(value);
            }
            if (lengths[256] == 0) throw Failure{"Missing end-of-block code in the compressed data"};

            Huffman lit, dist;
            const int litLeft = build(lit, lengths, nlen);
            if (litLeft < 0 || (litLeft > 0 && nlen - lit.count[0] != 1)) throw Failure{"Invalid literal/length code in the compressed data"};
            const int distLeft = build(dist, lengths + nlen, ndist);
            if (distLeft < 0 || (distLeft > 0 && ndist - dist.count[0] != 1)) throw Failure{"Invalid distance code in the compressed data"};
            inflateCodes(in, out, lit, dist);
        }

        void inflateStream(Input &in, Output &out) {
            bool last;
            do {
                last = in.bits(1) != 0;
                switch (in.bits(2)) {
                    case 0: inflateStored(in, out); break;
                    case 1: inflateFixed(in, out); break;
                    case 2: inflateDynamic(in, out); break;
                    default: throw Failure{"Invalid block type in the compressed data"};
                }
            } while (!last);
            in.alignToByte();
        }

        uint32_t readLe32(Input &in) {
            uint32_t v = 0;
            for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(in.byte()) << (8 * i);
            return v;
        }

        void skipZeroTerminated(Input &in) { while (in.byte() != 0) {} }

        void gunzipMember(Input &in, Output &out) {
            if (in.byte() != 0x1f || in.byte() != 0x8b) throw Failure{"Not a gzip file (bad magic number)"};
            if (in.byte() != 8) throw Failure{"Unsupported gzip compression method"};
            const uint8_t flags = in.byte();
            for (int i = 0; i < 6; ++i) in.byte();            // mtime(4), xfl, os
            if (flags & 4) {                                  // FEXTRA
                const unsigned n = in.byte() | (in.byte() << 8);
                for (unsigned i = 0; i < n; ++i) in.byte();
            }
            if (flags & 8) skipZeroTerminated(in);            // FNAME
            if (flags & 16) skipZeroTerminated(in);           // FCOMMENT
            if (flags & 2) { in.byte(); in.byte(); }          // FHCRC
            if (flags & 0xE0) throw Failure{"Unsupported gzip header flags"};

            out.startMember();
            inflateStream(in, out);
            const uint32_t crc = readLe32(in), size = readLe32(in);
            if (crc != out.crc()) throw Failure{"CRC mismatch: the compressed file is damaged"};
            if (size != out.memberSize()) throw Failure{"Size mismatch: the compressed file is damaged"};
        }
    } // namespace

    bool isGzipFile(const std::string &path) {
        std::ifstream f(pathFromUtf8(path), std::ios::binary);
        unsigned char magic[2] = {0, 0};
        return f.read(reinterpret_cast<char *>(magic), 2) && magic[0] == 0x1f && magic[1] == 0x8b;
    }

    bool gunzipMemory(const std::string &compressed, std::string &out, uint64_t maxOutput, std::string &error) {
        error.clear();
        out.clear();
        std::istringstream in(compressed, std::ios::binary);
        std::ostringstream outStream(std::ios::binary);
        try {
            Input input(in, nullptr);
            Output output(outStream, maxOutput);
            int members = 0;
            int next;
            while ((next = input.peek()) >= 0) {
                if (next == 0) { input.byte(); continue; }
                gunzipMember(input, output);
                ++members;
            }
            if (members == 0) throw Failure{"Not gzip data"};
            output.flush();
        } catch (const Failure &f) {
            error = f.message;
            return false;
        } catch (const Cancelled &) {
            return false;
        }
        out = outStream.str();
        return true;
    }

    uint64_t lastGunzipOutputSize() { return g_lastOutputSize; }

    bool gunzipFile(const std::string &inPath, const std::string &outPath, std::string &error, LoadControl *control) {
        error.clear();
        std::ifstream in(pathFromUtf8(inPath), std::ios::binary);
        if (!in) { error = "Failed to open file: " + inPath; return false; }
        std::ofstream outFile(pathFromUtf8(outPath), std::ios::binary | std::ios::trunc);
        if (!outFile) { error = "Cannot write the decompressed file " + outPath; return false; }
        if (control) {
            in.seekg(0, std::ios::end);
            control->totalBytes = static_cast<uint64_t>(in.tellg());
            in.seekg(0, std::ios::beg);
            control->bytesProcessed = 0;
        }

        try {
            Input input(in, control);
            Output output(outFile);
            int members = 0;
            while (true) {
                int next;
                while ((next = input.peek()) == 0) input.byte();   // zero padding between / after members
                if (next < 0) break;
                gunzipMember(input, output);
                ++members;
            }
            if (members == 0) throw Failure{"The file is empty or not a gzip file"};
            output.flush();
            g_lastOutputSize = output.total();
        } catch (const Failure &f) {
            error = f.message;
            return false;
        } catch (const Cancelled &) {
            return false;
        }
        outFile.flush();
        if (!outFile) { error = "Writing the decompressed file failed (disk full?)"; return false; }
        if (control) control->bytesProcessed = control->totalBytes.load();
        return true;
    }
} // namespace core

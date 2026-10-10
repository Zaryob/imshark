#include "hpack.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace dissect {

namespace {

const HeaderField kStaticTable[62] = {  // NOLINT(bugprone-throwing-static-initialization): fixed literals; failure is only out-of-memory at startup
    {"", ""},
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
};

// RFC 7541 Appendix B static Huffman table
struct HuffmanCode { uint32_t code; uint8_t bits; };
const HuffmanCode kHuffmanTable[257] = {
    {0x1ff8, 13}, // 0
    {0x7fffd8, 23}, // 1
    {0xfffffe2, 28}, // 2
    {0xfffffe3, 28}, // 3
    {0xfffffe4, 28}, // 4
    {0xfffffe5, 28}, // 5
    {0xfffffe6, 28}, // 6
    {0xfffffe7, 28}, // 7
    {0xfffffe8, 28}, // 8
    {0xffffea, 24}, // 9
    {0x3ffffffc, 30}, // 10
    {0xfffffe9, 28}, // 11
    {0xfffffea, 28}, // 12
    {0x3ffffffd, 30}, // 13
    {0xfffffeb, 28}, // 14
    {0xfffffec, 28}, // 15
    {0xfffffed, 28}, // 16
    {0xfffffee, 28}, // 17
    {0xfffffef, 28}, // 18
    {0xffffff0, 28}, // 19
    {0xffffff1, 28}, // 20
    {0xffffff2, 28}, // 21
    {0x3ffffffe, 30}, // 22
    {0xffffff3, 28}, // 23
    {0xffffff4, 28}, // 24
    {0xffffff5, 28}, // 25
    {0xffffff6, 28}, // 26
    {0xffffff7, 28}, // 27
    {0xffffff8, 28}, // 28
    {0xffffff9, 28}, // 29
    {0xffffffa, 28}, // 30
    {0xffffffb, 28}, // 31
    {0x14, 6}, // 32
    {0x3f8, 10}, // 33
    {0x3f9, 10}, // 34
    {0xffa, 12}, // 35
    {0x1ff9, 13}, // 36
    {0x15, 6}, // 37
    {0xf8, 8}, // 38
    {0x7fa, 11}, // 39
    {0x3fa, 10}, // 40
    {0x3fb, 10}, // 41
    {0xf9, 8}, // 42
    {0x7fb, 11}, // 43
    {0xfa, 8}, // 44
    {0x16, 6}, // 45
    {0x17, 6}, // 46
    {0x18, 6}, // 47
    {0x0, 5}, // 48
    {0x1, 5}, // 49
    {0x2, 5}, // 50
    {0x19, 6}, // 51
    {0x1a, 6}, // 52
    {0x1b, 6}, // 53
    {0x1c, 6}, // 54
    {0x1d, 6}, // 55
    {0x1e, 6}, // 56
    {0x1f, 6}, // 57
    {0x5c, 7}, // 58
    {0xfb, 8}, // 59
    {0x7ffc, 15}, // 60
    {0x20, 6}, // 61
    {0xffb, 12}, // 62
    {0x3fc, 10}, // 63
    {0x1ffa, 13}, // 64
    {0x21, 6}, // 65
    {0x5d, 7}, // 66
    {0x5e, 7}, // 67
    {0x5f, 7}, // 68
    {0x60, 7}, // 69
    {0x61, 7}, // 70
    {0x62, 7}, // 71
    {0x63, 7}, // 72
    {0x64, 7}, // 73
    {0x65, 7}, // 74
    {0x66, 7}, // 75
    {0x67, 7}, // 76
    {0x68, 7}, // 77
    {0x69, 7}, // 78
    {0x6a, 7}, // 79
    {0x6b, 7}, // 80
    {0x6c, 7}, // 81
    {0x6d, 7}, // 82
    {0x6e, 7}, // 83
    {0x6f, 7}, // 84
    {0x70, 7}, // 85
    {0x71, 7}, // 86
    {0x72, 7}, // 87
    {0xfc, 8}, // 88
    {0x73, 7}, // 89
    {0xfd, 8}, // 90
    {0x1ffb, 13}, // 91
    {0x7fff0, 19}, // 92
    {0x1ffc, 13}, // 93
    {0x3ffc, 14}, // 94
    {0x22, 6}, // 95
    {0x7ffd, 15}, // 96
    {0x3, 5}, // 97
    {0x23, 6}, // 98
    {0x4, 5}, // 99
    {0x24, 6}, // 100
    {0x5, 5}, // 101
    {0x25, 6}, // 102
    {0x26, 6}, // 103
    {0x27, 6}, // 104
    {0x6, 5}, // 105
    {0x74, 7}, // 106
    {0x75, 7}, // 107
    {0x28, 6}, // 108
    {0x29, 6}, // 109
    {0x2a, 6}, // 110
    {0x7, 5}, // 111
    {0x2b, 6}, // 112
    {0x76, 7}, // 113
    {0x2c, 6}, // 114
    {0x8, 5}, // 115
    {0x9, 5}, // 116
    {0x2d, 6}, // 117
    {0x77, 7}, // 118
    {0x78, 7}, // 119
    {0x79, 7}, // 120
    {0x7a, 7}, // 121
    {0x7b, 7}, // 122
    {0x7ffe, 15}, // 123
    {0x7fc, 11}, // 124
    {0x3ffd, 14}, // 125
    {0x1ffd, 13}, // 126
    {0xffffffc, 28}, // 127
    {0xfffe6, 20}, // 128
    {0x3fffd2, 22}, // 129
    {0xfffe7, 20}, // 130
    {0xfffe8, 20}, // 131
    {0x3fffd3, 22}, // 132
    {0x3fffd4, 22}, // 133
    {0x3fffd5, 22}, // 134
    {0x7fffd9, 23}, // 135
    {0x3fffd6, 22}, // 136
    {0x7fffda, 23}, // 137
    {0x7fffdb, 23}, // 138
    {0x7fffdc, 23}, // 139
    {0x7fffdd, 23}, // 140
    {0x7fffde, 23}, // 141
    {0xffffeb, 24}, // 142
    {0x7fffdf, 23}, // 143
    {0xffffec, 24}, // 144
    {0xffffed, 24}, // 145
    {0x3fffd7, 22}, // 146
    {0x7fffe0, 23}, // 147
    {0xffffee, 24}, // 148
    {0x7fffe1, 23}, // 149
    {0x7fffe2, 23}, // 150
    {0x7fffe3, 23}, // 151
    {0x7fffe4, 23}, // 152
    {0x1fffdc, 21}, // 153
    {0x3fffd8, 22}, // 154
    {0x7fffe5, 23}, // 155
    {0x3fffd9, 22}, // 156
    {0x7fffe6, 23}, // 157
    {0x7fffe7, 23}, // 158
    {0xffffef, 24}, // 159
    {0x3fffda, 22}, // 160
    {0x1fffdd, 21}, // 161
    {0xfffe9, 20}, // 162
    {0x3fffdb, 22}, // 163
    {0x3fffdc, 22}, // 164
    {0x7fffe8, 23}, // 165
    {0x7fffe9, 23}, // 166
    {0x1fffde, 21}, // 167
    {0x7fffea, 23}, // 168
    {0x3fffdd, 22}, // 169
    {0x3fffde, 22}, // 170
    {0xfffff0, 24}, // 171
    {0x1fffdf, 21}, // 172
    {0x3fffdf, 22}, // 173
    {0x7fffeb, 23}, // 174
    {0x7fffec, 23}, // 175
    {0x1fffe0, 21}, // 176
    {0x1fffe1, 21}, // 177
    {0x3fffe0, 22}, // 178
    {0x1fffe2, 21}, // 179
    {0x7fffed, 23}, // 180
    {0x3fffe1, 22}, // 181
    {0x7fffee, 23}, // 182
    {0x7fffef, 23}, // 183
    {0xfffea, 20}, // 184
    {0x3fffe2, 22}, // 185
    {0x3fffe3, 22}, // 186
    {0x3fffe4, 22}, // 187
    {0x7ffff0, 23}, // 188
    {0x3fffe5, 22}, // 189
    {0x3fffe6, 22}, // 190
    {0x7ffff1, 23}, // 191
    {0x3ffffe0, 26}, // 192
    {0x3ffffe1, 26}, // 193
    {0xfffeb, 20}, // 194
    {0x7fff1, 19}, // 195
    {0x3fffe7, 22}, // 196
    {0x7ffff2, 23}, // 197
    {0x3fffe8, 22}, // 198
    {0x1ffffec, 25}, // 199
    {0x3ffffe2, 26}, // 200
    {0x3ffffe3, 26}, // 201
    {0x3ffffe4, 26}, // 202
    {0x7ffffde, 27}, // 203
    {0x7ffffdf, 27}, // 204
    {0x3ffffe5, 26}, // 205
    {0xfffff1, 24}, // 206
    {0x1ffffed, 25}, // 207
    {0x7fff2, 19}, // 208
    {0x1fffe3, 21}, // 209
    {0x3ffffe6, 26}, // 210
    {0x7ffffe0, 27}, // 211
    {0x7ffffe1, 27}, // 212
    {0x3ffffe7, 26}, // 213
    {0x7ffffe2, 27}, // 214
    {0xfffff2, 24}, // 215
    {0x1fffe4, 21}, // 216
    {0x1fffe5, 21}, // 217
    {0x3ffffe8, 26}, // 218
    {0x3ffffe9, 26}, // 219
    {0xffffffd, 28}, // 220
    {0x7ffffe3, 27}, // 221
    {0x7ffffe4, 27}, // 222
    {0x7ffffe5, 27}, // 223
    {0xfffec, 20}, // 224
    {0xfffff3, 24}, // 225
    {0xfffed, 20}, // 226
    {0x1fffe6, 21}, // 227
    {0x3fffe9, 22}, // 228
    {0x1fffe7, 21}, // 229
    {0x1fffe8, 21}, // 230
    {0x7ffff3, 23}, // 231
    {0x3fffea, 22}, // 232
    {0x3fffeb, 22}, // 233
    {0x1ffffee, 25}, // 234
    {0x1ffffef, 25}, // 235
    {0xfffff4, 24}, // 236
    {0xfffff5, 24}, // 237
    {0x3ffffea, 26}, // 238
    {0x7ffff4, 23}, // 239
    {0x3ffffeb, 26}, // 240
    {0x7ffffe6, 27}, // 241
    {0x3ffffec, 26}, // 242
    {0x3ffffed, 26}, // 243
    {0x7ffffe7, 27}, // 244
    {0x7ffffe8, 27}, // 245
    {0x7ffffe9, 27}, // 246
    {0x7ffffea, 27}, // 247
    {0x7ffffeb, 27}, // 248
    {0xffffffe, 28}, // 249
    {0x7ffffec, 27}, // 250
    {0x7ffffed, 27}, // 251
    {0x7ffffee, 27}, // 252
    {0x7ffffef, 27}, // 253
    {0x7fffff0, 27}, // 254
    {0x3ffffee, 26}, // 255
    {0x3fffffff, 30}, // 256
};


struct TrieNode {
    int16_t next[2] = {-1, -1};
    int16_t symbol = -1;
};

class HuffmanTrie {
public:
    HuffmanTrie() {
        nodes.reserve(600);
        nodes.push_back(TrieNode{}); // Root node at 0

        for (int sym = 0; sym < 257; ++sym) {
            uint32_t code = kHuffmanTable[sym].code;
            uint8_t bits = kHuffmanTable[sym].bits;
            int curr = 0;
            for (int b = bits - 1; b >= 0; --b) {
                int bit = (code >> b) & 1;
                if (nodes[curr].next[bit] == -1) {
                    int nextIdx = static_cast<int>(nodes.size());
                    nodes.push_back(TrieNode{});
                    nodes[curr].next[bit] = static_cast<int16_t>(nextIdx);
                }
                curr = nodes[curr].next[bit];
            }
            nodes[curr].symbol = static_cast<int16_t>(sym);
        }
    }

    const std::vector<TrieNode> &getNodes() const { return nodes; }

private:
    std::vector<TrieNode> nodes;
};

const HuffmanTrie &huffmanTrieInstance() {
    static const HuffmanTrie trie;
    return trie;
}

} // namespace

bool hpackHuffmanDecode(const uint8_t *data, size_t length, std::string &out) {
    out.clear();
    const auto &nodes = huffmanTrieInstance().getNodes();
    int node = 0;

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];
        for (int b = 7; b >= 0; --b) {
            int bit = (byte >> b) & 1;
            node = nodes[node].next[bit];
            if (node < 0) return false;
            if (nodes[node].symbol >= 0) {
                if (nodes[node].symbol == 256) return false; // EOS is forbidden in decoded data
                out.push_back(static_cast<char>(nodes[node].symbol));
                node = 0;
            }
        }
    }

    // Check padding: if any bits remain, they must be the prefix of EOS (all 1-bits) and <= 7 bits
    if (node != 0) {
        int testNode = node;
        while (testNode >= 0 && nodes[testNode].symbol < 0) {
            testNode = nodes[testNode].next[1];
        }
        if (testNode < 0 || nodes[testNode].symbol != 256) return false;
    }

    return true;
}

void HpackContext::setMaxTableSize(size_t maxTableSize) {
    maxTableSize_ = maxTableSize;
    evict();
}

void HpackContext::clear() {
    dynamicTable_.clear();
    currentTableSize_ = 0;
}

void HpackContext::evict() {
    while (currentTableSize_ > maxTableSize_ && !dynamicTable_.empty()) {
        currentTableSize_ -= (dynamicTable_.back().name.size() + dynamicTable_.back().value.size() + 32);
        dynamicTable_.pop_back();
    }
}

void HpackContext::addDynamic(const std::string &name, const std::string &value) {
    const size_t entrySize = name.size() + value.size() + 32;
    if (entrySize > maxTableSize_) {
        clear();
        return;
    }
    while (currentTableSize_ + entrySize > maxTableSize_ && !dynamicTable_.empty()) {
        currentTableSize_ -= (dynamicTable_.back().name.size() + dynamicTable_.back().value.size() + 32);
        dynamicTable_.pop_back();
    }
    dynamicTable_.push_front({name, value});
    currentTableSize_ += entrySize;
}

bool HpackContext::getEntry(size_t index, std::string &name, std::string &value) const {
    if (index >= 1 && index <= 61) {
        name = kStaticTable[index].name;
        value = kStaticTable[index].value;
        return true;
    }
    size_t dynIndex = index - 62;
    if (dynIndex < dynamicTable_.size()) {
        name = dynamicTable_[dynIndex].name;
        value = dynamicTable_[dynIndex].value;
        return true;
    }
    return false;
}

bool HpackContext::readInt(const uint8_t *&p, const uint8_t *end, uint8_t prefixBits, uint32_t &out) {
    if (p >= end) return false;
    uint8_t mask = static_cast<uint8_t>((1u << prefixBits) - 1);
    uint32_t val = (*p++) & mask;
    if (val < mask) {
        out = val;
        return true;
    }
    uint32_t m = 0;
    while (p < end) {
        uint8_t b = *p++;
        val += static_cast<uint32_t>(b & 0x7F) << m;
        m += 7;
        if ((b & 0x80) == 0) {
            out = val;
            return true;
        }
        if (m > 28) return false; // Prevent overflow
    }
    return false;
}

bool HpackContext::readString(const uint8_t *&p, const uint8_t *end, std::string &out) {
    if (p >= end) return false;
    bool huffman = (*p & 0x80) != 0;
    uint32_t len = 0;
    if (!readInt(p, end, 7, len)) return false;
    if (static_cast<size_t>(end - p) < len) return false;
    if (huffman) {
        if (!hpackHuffmanDecode(p, len, out)) return false;
    } else {
        out.assign(reinterpret_cast<const char *>(p), len);
    }
    p += len;
    return true;
}

bool HpackContext::decode(const char *data, size_t length, std::vector<HeaderField> &headers) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
    const uint8_t *end = p + length;

    while (p < end) {
        uint8_t b = *p;
        if (b & 0x80) {
            // Indexed Header Field Representation (1xxxxxxx)
            uint32_t index = 0;
            if (!readInt(p, end, 7, index)) return false;
            std::string name, val;
            if (!getEntry(index, name, val)) return false;
            headers.push_back({std::move(name), std::move(val)});
        } else if ((b & 0xC0) == 0x40) {
            // Literal Header Field with Incremental Indexing (01xxxxxx)
            uint32_t index = 0;
            if (!readInt(p, end, 6, index)) return false;
            std::string name, val;
            if (index == 0) {
                if (!readString(p, end, name)) return false;
            } else {
                std::string dummyVal;
                if (!getEntry(index, name, dummyVal)) return false;
            }
            if (!readString(p, end, val)) return false;
            addDynamic(name, val);
            headers.push_back({std::move(name), std::move(val)});
        } else if ((b & 0xE0) == 0x20) {
            // Dynamic Table Size Update (001xxxxx)
            uint32_t newMax = 0;
            if (!readInt(p, end, 5, newMax)) return false;
            setMaxTableSize(newMax);
        } else if ((b & 0xF0) == 0x10 || (b & 0xF0) == 0x00) {
            // Literal Header Field without Indexing (0000xxxx) or Never Indexed (0001xxxx)
            uint32_t index = 0;
            if (!readInt(p, end, 4, index)) return false;
            std::string name, val;
            if (index == 0) {
                if (!readString(p, end, name)) return false;
            } else {
                std::string dummyVal;
                if (!getEntry(index, name, dummyVal)) return false;
            }
            if (!readString(p, end, val)) return false;
            headers.push_back({std::move(name), std::move(val)});
        } else {
            return false;
        }
    }
    return true;
}

} // namespace dissect

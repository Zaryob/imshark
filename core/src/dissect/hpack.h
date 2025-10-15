#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace dissect {

struct HeaderField {
    std::string name;
    std::string value;
};

/// Decodes data using the HPACK canonical Huffman tree (RFC 7541 Appendix B).
bool hpackHuffmanDecode(const uint8_t *data, size_t length, std::string &out);

/// HPACK Decoder Context maintaining the dynamic header table (RFC 7541).
class HpackContext {
public:
    static constexpr size_t kDefaultMaxTableSize = 4096;

    explicit HpackContext(size_t maxTableSize = kDefaultMaxTableSize)
        : maxTableSize_(maxTableSize) {}

    void setMaxTableSize(size_t maxTableSize);
    size_t maxTableSize() const { return maxTableSize_; }
    size_t currentTableSize() const { return currentTableSize_; }
    size_t dynamicTableEntryCount() const { return dynamicTable_.size(); }

    /// Decodes an HPACK-encoded header block into a list of name/value pairs.
    /// Returns true on success, false if the block is malformed.
    bool decode(const char *data, size_t length, std::vector<HeaderField> &headers);

    void clear();

    /// Table lookup by 1-based index (1..61 static, 62+ dynamic)
    bool getEntry(size_t index, std::string &name, std::string &value) const;

private:
    bool readInt(const uint8_t *&p, const uint8_t *end, uint8_t prefixBits, uint32_t &out);
    bool readString(const uint8_t *&p, const uint8_t *end, std::string &out);
    void addDynamic(const std::string &name, const std::string &value);
    void evict();

    size_t maxTableSize_ = kDefaultMaxTableSize;
    size_t currentTableSize_ = 0;
    std::deque<HeaderField> dynamicTable_;
};

} // namespace dissect

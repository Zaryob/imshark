#include <gtest/gtest.h>

#include <random>
#include <string>
#include <vector>

#include "dissect/hpack.h"

using namespace dissect;

TEST(Http2Hpack, HuffmanDecodeVectors) {
    // RFC 7541 C.4.1: "www.example.com"
    const uint8_t v1[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    std::string s1;
    EXPECT_TRUE(hpackHuffmanDecode(v1, sizeof(v1), s1));
    EXPECT_EQ(s1, "www.example.com");

    // RFC 7541 C.4.2: "no-cache"
    const uint8_t v2[] = { 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    std::string s2;
    EXPECT_TRUE(hpackHuffmanDecode(v2, sizeof(v2), s2));
    EXPECT_EQ(s2, "no-cache");

    // RFC 7541 C.4.3: "custom-key"
    const uint8_t v3[] = { 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
    std::string s3;
    EXPECT_TRUE(hpackHuffmanDecode(v3, sizeof(v3), s3));
    EXPECT_EQ(s3, "custom-key");
}

TEST(Http2Hpack, StaticTableEntries) {
    HpackContext hpack;
    std::string name, val;
    EXPECT_TRUE(hpack.getEntry(2, name, val));
    EXPECT_EQ(name, ":method");
    EXPECT_EQ(val, "GET");

    EXPECT_TRUE(hpack.getEntry(3, name, val));
    EXPECT_EQ(name, ":method");
    EXPECT_EQ(val, "POST");

    EXPECT_TRUE(hpack.getEntry(4, name, val));
    EXPECT_EQ(name, ":path");
    EXPECT_EQ(val, "/");

    EXPECT_TRUE(hpack.getEntry(14, name, val));
    EXPECT_EQ(name, ":status");
    EXPECT_EQ(val, "500");

    EXPECT_FALSE(hpack.getEntry(0, name, val));
    EXPECT_FALSE(hpack.getEntry(62, name, val)); // dynamic table empty
}

TEST(Http2Hpack, DecodeHeaderBlock) {
    HpackContext hpack;
    std::vector<HeaderField> headers;

    // RFC 7541 C.2.1: Literal Header Field with Indexing (index 4 for :path, value "/sample/path")
    const uint8_t block[] = {
        0x82, // Indexed: index 2 (:method: GET)
        0x44, 0x0c, '/', 's', 'a', 'm', 'p', 'l', 'e', '/', 'p', 'a', 't', 'h', // Literal with indexing
        0x87  // Indexed: index 7 (:scheme: https)
    };

    EXPECT_TRUE(hpack.decode(reinterpret_cast<const char*>(block), sizeof(block), headers));
    ASSERT_EQ(headers.size(), 3u);
    EXPECT_EQ(headers[0].name, ":method");
    EXPECT_EQ(headers[0].value, "GET");
    EXPECT_EQ(headers[1].name, ":path");
    EXPECT_EQ(headers[1].value, "/sample/path");
    EXPECT_EQ(headers[2].name, ":scheme");
    EXPECT_EQ(headers[2].value, "https");

    // Dynamic table should now contain entry 62: :path -> /sample/path
    std::string dname, dval;
    EXPECT_TRUE(hpack.getEntry(62, dname, dval));
    EXPECT_EQ(dname, ":path");
    EXPECT_EQ(dval, "/sample/path");
}

// RFC 7541 appendix C.3: three requests on one connection without Huffman coding; the dynamic table carries over.
TEST(Http2Hpack, RequestSequenceKeepsTheDynamicTable) {
    HpackContext hpack;
    auto decode = [&](const std::vector<uint8_t> &block, std::vector<HeaderField> &out) {
        return hpack.decode(reinterpret_cast<const char *>(block.data()), block.size(), out);
    };
    std::vector<HeaderField> h;
    ASSERT_TRUE(decode({0x82, 0x86, 0x84, 0x41, 0x0f, 'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'}, h));
    ASSERT_EQ(h.size(), 4u);
    EXPECT_EQ(h[3].name, ":authority");
    EXPECT_EQ(h[3].value, "www.example.com");
    EXPECT_EQ(hpack.currentTableSize(), 57u);

    h.clear();
    ASSERT_TRUE(decode({0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n','o','-','c','a','c','h','e'}, h));
    ASSERT_EQ(h.size(), 5u);
    EXPECT_EQ(h[3].value, "www.example.com") << "index 62 comes from the first request";
    EXPECT_EQ(h[4].name, "cache-control");
    EXPECT_EQ(hpack.currentTableSize(), 110u);

    h.clear();
    ASSERT_TRUE(decode({0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 'c','u','s','t','o','m','-','k','e','y', 0x0c, 'c','u','s','t','o','m','-','v','a','l','u','e'}, h));
    ASSERT_EQ(h.size(), 5u);
    EXPECT_EQ(h[2].value, "/index.html");
    EXPECT_EQ(h[3].value, "www.example.com");
    EXPECT_EQ(h[4].name, "custom-key");
    EXPECT_EQ(hpack.currentTableSize(), 164u);
    EXPECT_EQ(hpack.dynamicTableEntryCount(), 3u);
}

TEST(Http2Hpack, DamagedBlocksAreRejectedNotCrashes) {
    std::mt19937 rng(11);
    const std::vector<uint8_t> seed = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m', 0x40, 0x0a, 'c','u','s','t','o','m','-','k','e','y', 0x0c, 'c','u','s','t','o','m','-','v','a','l','u','e'};
    for (int i = 0; i < 20000; ++i) {
        std::vector<uint8_t> b = seed;
        b.resize(rng() % (b.size() + 1));
        for (unsigned k = rng() % 4; k > 0 && !b.empty(); --k) b[rng() % b.size()] = static_cast<uint8_t>(rng());
        HpackContext hpack(rng() % 2 ? 4096 : 64);
        std::vector<HeaderField> h;
        hpack.decode(reinterpret_cast<const char *>(b.data()), b.size(), h);
        EXPECT_LE(hpack.currentTableSize(), hpack.maxTableSize());
    }
    // an index far beyond both tables
    HpackContext hpack;
    std::vector<HeaderField> h;
    const uint8_t beyond[] = {0xff, 0xff, 0xff, 0xff, 0x0f};
    EXPECT_FALSE(hpack.decode(reinterpret_cast<const char *>(beyond), sizeof(beyond), h));
}

#include <gtest/gtest.h>

#include <dissect/xdr.h>

TEST(XdrReader, BasicTypes) {
    // 32-bit int (42), unsigned int (100), bool (true), hyper (0x1122334455667788)
    std::vector<uint8_t> buf = {
        0x00, 0x00, 0x00, 0x2a,
        0x00, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x00, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };

    dissect::XdrReader reader(buf.data(), buf.size());
    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.readInt(), 42);
    EXPECT_EQ(reader.readUnsignedInt(), 100U);
    EXPECT_TRUE(reader.readBool());
    EXPECT_EQ(reader.readHyper(), 0x1122334455667788LL);
    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.remaining(), 0U);
}

TEST(XdrReader, StringsAndPadding) {
    // String "hello" (length 5 -> 5 bytes + 3 padding bytes = 8 bytes total)
    // Followed by unsigned int 999 (0x000003e7)
    std::vector<uint8_t> buf = {
        0x00, 0x00, 0x00, 0x05, // length 5
        'h', 'e', 'l', 'l',
        'o', 0x00, 0x00, 0x00, // padded with 3 zeros
        0x00, 0x00, 0x03, 0xe7  // 999
    };

    dissect::XdrReader reader(buf.data(), buf.size());
    EXPECT_EQ(reader.readString(), "hello");
    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.readUnsignedInt(), 999U);
    EXPECT_TRUE(reader.ok());
    EXPECT_EQ(reader.remaining(), 0U);
}

TEST(XdrReader, TruncationAndBounds) {
    // Length specifies 10 bytes but buffer ends prematurely
    std::vector<uint8_t> buf = {
        0x00, 0x00, 0x00, 0x0a,
        'a', 'b', 'c'
    };

    dissect::XdrReader reader(buf.data(), buf.size());
    EXPECT_EQ(reader.readString(), "");
    EXPECT_FALSE(reader.ok());
}

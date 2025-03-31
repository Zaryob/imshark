#include <gtest/gtest.h>

#include <network/utils.h>

TEST(Utils, PlainDomainName) {
    const char data[] = "\x07" "example\x03" "com\x00" "rest";
    size_t off = 0;
    EXPECT_EQ(network::getDomainName(data, off, sizeof(data) - 1), "example.com");
    EXPECT_EQ(off, 13u);
}

TEST(Utils, CompressionPointer) {
    // name at 0, then a record that points back to it
    const char data[] = "\x03" "foo\x00" "\xc0\x00" "tail";
    size_t off = 5;
    EXPECT_EQ(network::getDomainName(data, off, sizeof(data) - 1), "foo");
    EXPECT_EQ(off, 7u) << "a pointer consumes exactly two bytes";
}

TEST(Utils, MalformedNamesStayInBounds) {
    const char loop[] = "\xc0\x00";                        // pointer to itself
    size_t off = 0;
    network::getDomainName(loop, off, 2);                   // must terminate
    const char longLabel[] = "\x3f" "abc";                  // label runs past the buffer
    off = 0;
    EXPECT_EQ(network::getDomainName(longLabel, off, 4), "");
    const char truncPtr[] = "\xc0";                         // pointer missing its second byte
    off = 0;
    network::getDomainName(truncPtr, off, 1);
    SUCCEED();
}

TEST(Utils, MacString) {
    const uint8_t mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff};
    EXPECT_EQ(network::getMACAddressString(mac), "00:1a:2b:3c:4d:ff");
}

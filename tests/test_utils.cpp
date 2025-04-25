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

// ---- portable byte order / address formatting ------------------------------------------------------

#include <random>

#include <network/byteorder.h>

#ifndef _WIN32
#include <arpa/inet.h> // reference implementation to compare against (POSIX only)


TEST(ByteOrder, MatchesTheSystemFunctions) {
    for (uint32_t v: {0u, 1u, 0x1234u, 0xffffu, 0xdeadbeefu, 0x01020304u}) {
        EXPECT_EQ(network::ntoh32(v), ntohl(v));
        EXPECT_EQ(network::hton32(v), htonl(v));
        EXPECT_EQ(network::ntoh16(static_cast<uint16_t>(v)), ntohs(static_cast<uint16_t>(v)));
        EXPECT_EQ(network::hton16(static_cast<uint16_t>(v)), htons(static_cast<uint16_t>(v)));
    }
    EXPECT_EQ(network::bswap32(0x01020304u), 0x04030201u);
}

TEST(AddressFormat, Ipv4MatchesInetNtop) {
    std::mt19937 rng(1);
    for (int i = 0; i < 2000; ++i) {
        uint8_t a[4];
        for (auto &b: a) b = static_cast<uint8_t>(rng());
        char ref[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, a, ref, sizeof ref);
        EXPECT_EQ(network::formatIPv4(a), ref);
    }
}

TEST(AddressFormat, Ipv6MatchesInetNtop) {
    const char *known[] = {"::", "::1", "1::", "2001:db8::1", "fe80::1:2", "::ffff:1.2.3.4", "1:0:0:2:0:0:0:3",
                           "1:2:3:4:5:6:7:8", "0:0:0:0:0:0:0:2", "::1.2.3.4", "2001:db8:0:0:1:0:0:1", "ff02::fb"};
    for (const char *text: known) {
        uint8_t a[16];
        ASSERT_EQ(inet_pton(AF_INET6, text, a), 1) << text;
        char ref[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, a, ref, sizeof ref);
        EXPECT_EQ(network::formatIPv6(a), ref) << text;
    }
    // random addresses, biased towards zero groups so that compression is exercised
    std::mt19937 rng(2);
    for (int i = 0; i < 20000; ++i) {
        uint8_t a[16];
        for (int g = 0; g < 8; ++g) {
            const bool zero = rng() % 3 != 0;
            const uint16_t v = zero ? 0 : (rng() % 4 == 0 ? static_cast<uint16_t>(rng()) : static_cast<uint16_t>(rng() % 3));
            a[2 * g] = static_cast<uint8_t>(v >> 8);
            a[2 * g + 1] = static_cast<uint8_t>(v);
        }
        char ref[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, a, ref, sizeof ref);
        ASSERT_EQ(network::formatIPv6(a), ref);
    }
}
#endif // _WIN32

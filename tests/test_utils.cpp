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

// ---- IP address parsing ----------------------------------------------------------------------------

#include <network/address.h>

TEST(AddressParse, Ipv4) {
    EXPECT_EQ(*network::parseIPv4("10.0.0.1"), (std::array<uint8_t, 4>{10, 0, 0, 1}));
    EXPECT_EQ(*network::parseIPv4("255.255.255.255"), (std::array<uint8_t, 4>{255, 255, 255, 255}));
    for (const char *bad: {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.04", "a.b.c.d", "1.2.3.4 ", " 1.2.3.4", "1..2.3", "1.2.3.", "01.2.3.4", "1.2.3.4/8"}) {
        EXPECT_FALSE(network::parseIPv4(bad)) << bad;
    }
}

TEST(AddressParse, Ipv6) {
    EXPECT_EQ(network::formatIPv6(network::parseIPv6("2001:db8::1")->data()), "2001:db8::1");
    EXPECT_EQ(network::formatIPv6(network::parseIPv6("::")->data()), "::");
    EXPECT_EQ(network::formatIPv6(network::parseIPv6("::1")->data()), "::1");
    EXPECT_EQ(network::formatIPv6(network::parseIPv6("::ffff:1.2.3.4")->data()), "::ffff:1.2.3.4");
    EXPECT_EQ(network::formatIPv6(network::parseIPv6("1:2:3:4:5:6:7:8")->data()), "1:2:3:4:5:6:7:8");
    for (const char *bad: {"", ":", ":::", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1", ":1:2:3:4:5:6:7",
                           "1:2:3:4:5:6:7:8::", "::1.2.3", "1.2.3.4", "1:2:3:4:5:6:7::8"}) {
        EXPECT_FALSE(network::parseIPv6(bad)) << bad;
    }
}

TEST(AddressParse, Cidr) {
    const auto net = network::parseIpNetwork("10.0.0.0/8");
    ASSERT_TRUE(net);
    EXPECT_TRUE(net->contains(*network::parseIpAddress("10.255.1.2")));
    EXPECT_FALSE(net->contains(*network::parseIpAddress("11.0.0.1")));
    EXPECT_FALSE(net->contains(*network::parseIpAddress("::1"))) << "families never match";

    const auto odd = network::parseIpNetwork("192.168.1.128/25");
    EXPECT_TRUE(odd->contains(*network::parseIpAddress("192.168.1.200")));
    EXPECT_FALSE(odd->contains(*network::parseIpAddress("192.168.1.100")));

    const auto v6 = network::parseIpNetwork("2001:db8::/32");
    EXPECT_TRUE(v6->contains(*network::parseIpAddress("2001:db8:ffff::1")));
    EXPECT_FALSE(v6->contains(*network::parseIpAddress("2001:db9::1")));

    EXPECT_EQ(network::parseIpNetwork("1.2.3.4")->prefix, 32);
    EXPECT_EQ(network::parseIpNetwork("::1")->prefix, 128);
    EXPECT_TRUE(network::parseIpNetwork("0.0.0.0/0")->contains(*network::parseIpAddress("8.8.8.8")));
    for (const char *bad: {"10.0.0.0/33", "10.0.0.0/", "10.0.0.0/-1", "10.0.0.0/8x", "::/129", "/8"}) {
        EXPECT_FALSE(network::parseIpNetwork(bad)) << bad;
    }
}

#ifndef _WIN32
#include <cctype>
#include <cstring>
#include <random>

// Differential test: the strict parsers agree with inet_pton wherever the latter is well defined
TEST(AddressParse, Ipv6AgreesWithInetPton) {
    std::mt19937 rng(5);
    const char *alphabet[] = {"0", "1", "a", "ff", "db8", "2001", "ffff", "0000", ":", "::", ":", ".", "1.2.3.4"};
    for (int i = 0; i < 40000; ++i) {
        std::string s;
        for (int n = rng() % 12; n > 0; --n) s += alphabet[rng() % (sizeof(alphabet) / sizeof(*alphabet))];
        // macOS' inet_pton accepts groups with more than 4 hex digits ("0000ff::"); RFC 4291 (and glibc) do not
        bool longGroup = false;
        for (size_t a = 0, run = 0; a <= s.size(); ++a) {
            if (a < s.size() && std::isxdigit(static_cast<unsigned char>(s[a]))) { if (++run > 4) longGroup = true; }
            else run = 0;
        }
        // ... and an embedded IPv4 part with a leading zero ("::01.2.3.4"), which the strict parser rejects
        for (size_t a = 0; a + 1 < s.size(); ++a) {
            if (s[a] == '0' && std::isdigit(static_cast<unsigned char>(s[a + 1])) && (a == 0 || !std::isxdigit(static_cast<unsigned char>(s[a - 1])))
                && s.find('.', a) != std::string::npos && s.find(':', a) == std::string::npos) longGroup = true;
        }
        if (longGroup) continue;

        uint8_t ref[16];
        const bool refOk = inet_pton(AF_INET6, s.c_str(), ref) == 1;
        const auto mine = network::parseIPv6(s);
        ASSERT_EQ(refOk, mine.has_value()) << "'" << s << "'";
        if (refOk) ASSERT_EQ(std::memcmp(ref, mine->data(), 16), 0) << s;
    }
}

TEST(AddressParse, Ipv4AgreesWithInetPtonOnCanonicalForms) {
    std::mt19937 rng(6);
    for (int i = 0; i < 5000; ++i) {
        const std::string s = std::to_string(rng() % 300) + "." + std::to_string(rng() % 300) + "." +
                              std::to_string(rng() % 300) + "." + std::to_string(rng() % 300);
        uint8_t ref[4];
        const bool refOk = inet_pton(AF_INET, s.c_str(), ref) == 1;
        const auto mine = network::parseIPv4(s);
        ASSERT_EQ(refOk, mine.has_value()) << s;
        if (refOk) ASSERT_EQ(std::memcmp(ref, mine->data(), 4), 0);
    }
}
#endif

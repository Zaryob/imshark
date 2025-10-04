#include <gtest/gtest.h>

#include <dissect/asn1.h>
#include <dissect/reader.h>

using namespace dissect;

TEST(ByteReader, BasicEndianReads) {
    const uint8_t buf[] = {
        0x01,                   // u8
        0x12, 0x34,             // u16_be = 0x1234, u16_le = 0x3412
        0x01, 0x02, 0x03,       // u24_be = 0x010203
        0x10, 0x20, 0x30, 0x40, // u32_be = 0x10203040
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 // u64_be
    };
    ByteReader r(buf, sizeof(buf));
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(r.size(), sizeof(buf));
    EXPECT_EQ(r.remaining(), sizeof(buf));

    EXPECT_EQ(r.u8(), 0x01);
    EXPECT_EQ(r.u16_be(), 0x1234);

    ByteReader r_le(buf + 1, 2);
    EXPECT_EQ(r_le.u16_le(), 0x3412);

    EXPECT_EQ(r.u24_be(), 0x010203u);
    EXPECT_EQ(r.u32_be(), 0x10203040u);
    EXPECT_EQ(r.u64_be(), 0x0102030405060708ull);
    EXPECT_EQ(r.remaining(), 0u);
    EXPECT_TRUE(r.empty());
    EXPECT_TRUE(r.ok());

    // Reading past the end must fail and return 0
    EXPECT_EQ(r.u8(), 0);
    EXPECT_FALSE(r.ok());
}

TEST(ByteReader, SubReaderAndSlices) {
    const char text[] = "Hello, World! 12345";
    ByteReader r(text, sizeof(text) - 1);
    EXPECT_EQ(r.readString(5), "Hello");
    EXPECT_TRUE(r.skip(2)); // Skip ", "

    ByteReader child = r.sub(5);
    EXPECT_TRUE(child.ok());
    EXPECT_EQ(child.remainingString(), "World");

    EXPECT_EQ(r.remainingString(), "! 12345");
    EXPECT_TRUE(r.ok());

    // Sub over remaining must fail
    ByteReader bad = r.sub(10);
    EXPECT_FALSE(bad.ok());
    EXPECT_FALSE(r.ok());
}

TEST(ByteReader, BoundaryChecks) {
    const uint8_t small[] = {0xaa, 0xbb};
    ByteReader r(small, sizeof(small));
    EXPECT_EQ(r.u32_be(), 0u);
    EXPECT_FALSE(r.ok());
    // Subsequent reads stay failed
    EXPECT_EQ(r.u8(), 0);
    EXPECT_FALSE(r.ok());
}

TEST(BerAsn1, DefiniteShortLengthInteger) {
    // INTEGER 42 (0x2a) -> Tag 0x02, Len 0x01, Val 0x2a
    const uint8_t der[] = {0x02, 0x01, 0x2a};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    EXPECT_EQ(t.rawTag, 0x02);
    EXPECT_TRUE(t.isUniversal(asn1::tag::Integer));
    EXPECT_FALSE(t.constructed);
    EXPECT_EQ(t.length, 1u);
    EXPECT_EQ(t.total, 3u);

    int64_t v = 0;
    EXPECT_TRUE(t.asInt64(v));
    EXPECT_EQ(v, 42);

    uint64_t uv = 0;
    EXPECT_TRUE(t.asUint64(uv));
    EXPECT_EQ(uv, 42u);
}

TEST(BerAsn1, NegativeInteger) {
    // INTEGER -1 -> Tag 0x02, Len 0x01, Val 0xff
    const uint8_t der[] = {0x02, 0x01, 0xff};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    int64_t v = 0;
    EXPECT_TRUE(t.asInt64(v));
    EXPECT_EQ(v, -1);
}

TEST(BerAsn1, TwoByteLongInteger64Bit) {
    // INTEGER 0x0102030405060708 (8 bytes)
    const uint8_t der[] = {0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    int64_t v = 0;
    EXPECT_TRUE(t.asInt64(v));
    EXPECT_EQ(v, 0x0102030405060708ll);
}

TEST(BerAsn1, IntegerWithLeadingZeroForUnsigned) {
    // Positive 32-bit integer with high bit set: needs leading 0x00
    // 0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x01 = 2147483649
    const uint8_t der[] = {0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x01};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    uint64_t uv = 0;
    EXPECT_TRUE(t.asUint64(uv));
    EXPECT_EQ(uv, 2147483649ull);
}

TEST(BerAsn1, MultiByteTagNumber) {
    // Context-specific [35] constructed:
    // First byte: class Context(10) | constructed(1) | 0x1f = 0xbf
    // Tag 35 = 35 < 128 -> 0x23
    // Length: 0x02, Content: 0x05, 0x00 (NULL)
    const uint8_t der[] = {0xbf, 0x23, 0x02, 0x05, 0x00};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    EXPECT_TRUE(t.isContext(35));
    EXPECT_TRUE(t.constructed);
    EXPECT_EQ(t.tagNumber, 35u);
    EXPECT_EQ(t.length, 2u);
    EXPECT_EQ(t.total, 5u);
}

TEST(BerAsn1, LongFormLength) {
    // OCTET STRING with length 260
    // Tag: 0x04
    // Length: 0x82 0x01 0x04 (2 octets: 260)
    std::vector<uint8_t> der = {0x04, 0x82, 0x01, 0x04};
    der.resize(4 + 260, 'A');
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der.data(), der.size(), t));
    EXPECT_EQ(t.length, 260u);
    EXPECT_EQ(t.headerLength, 4u);
    EXPECT_EQ(t.total, 264u);
}

TEST(BerAsn1, IndefiniteLengthWithEoc) {
    // BER Indefinite Length SEQUENCE:
    // 0x30, 0x80 (indefinite)
    //   0x02, 0x01, 0x01 (INTEGER 1)
    //   0x02, 0x01, 0x02 (INTEGER 2)
    // 0x00, 0x00 (EOC)
    const uint8_t der[] = {
        0x30, 0x80,
        0x02, 0x01, 0x01,
        0x02, 0x01, 0x02,
        0x00, 0x00
    };
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    EXPECT_TRUE(t.indefinite);
    EXPECT_TRUE(t.constructed);
    EXPECT_EQ(t.length, 6u);
    EXPECT_EQ(t.total, 10u);

    std::vector<int64_t> nums;
    EXPECT_TRUE(eachChild(t, [&](const BerTlv &c) {
        int64_t v = 0;
        if (c.asInt64(v)) nums.push_back(v);
    }));
    ASSERT_EQ(nums.size(), 2u);
    EXPECT_EQ(nums[0], 1);
    EXPECT_EQ(nums[1], 2);
}

TEST(BerAsn1, OidDecoding) {
    // RFC 3416 OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    // 1.3 -> 43 (0x2b)
    // .6 -> 0x06
    // .1 -> 0x01
    // .2 -> 0x02
    // .1 -> 0x01
    // .1 -> 0x01
    // .1 -> 0x01
    // .0 -> 0x00
    const uint8_t der[] = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
    BerTlv t;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), t));
    EXPECT_TRUE(t.isUniversal(asn1::tag::Oid));
    EXPECT_EQ(t.asOid(), "1.3.6.1.2.1.1.1.0");

    // Enterprise OID with sub-ids > 127:
    // 1.3.6.1.4.1.8072.3.2.10 (net-snmp)
    // 8072 = (63 << 7) | 8 = 0x80 | 63 (0xbf), 0x08
    const uint8_t ent[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x0a};
    BerTlv entTlv;
    EXPECT_TRUE(readBerTlv(ent, sizeof(ent), entTlv));
    EXPECT_EQ(entTlv.asOid(), "1.3.6.1.4.1.8072.3.2.10");
}

TEST(BerAsn1, SequenceIteration) {
    // SEQUENCE { INTEGER 10, UTF8String "test" }
    const uint8_t der[] = {
        0x30, 0x09,
        0x02, 0x01, 0x0a,
        0x0c, 0x04, 't', 'e', 's', 't'
    };
    BerTlv seq;
    EXPECT_TRUE(readBerTlv(der, sizeof(der), seq));
    EXPECT_TRUE(seq.constructed);

    int count = 0;
    EXPECT_TRUE(eachChild(seq, [&](const BerTlv &c) {
        if (count == 0) {
            EXPECT_TRUE(c.isUniversal(asn1::tag::Integer));
            int64_t val = 0;
            EXPECT_TRUE(c.asInt64(val));
            EXPECT_EQ(val, 10);
        } else if (count == 1) {
            EXPECT_TRUE(c.isUniversal(asn1::tag::Utf8String));
            EXPECT_EQ(c.asString(), "test");
        }
        count++;
    }));
    EXPECT_EQ(count, 2);
}

TEST(BerAsn1, MalformedAndOverlongInputs) {
    // 1. Empty buffer
    BerTlv t;
    EXPECT_FALSE(readBerTlv(nullptr, 0, t));

    // 2. Length truncated (needs 5 bytes, only 2 provided)
    const uint8_t trunc[] = {0x02, 0x05, 0x01, 0x02};
    EXPECT_FALSE(readBerTlv(trunc, sizeof(trunc), t));

    // 3. Length count > 4 (disallowed)
    const uint8_t hugeLen[] = {0x04, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_FALSE(readBerTlv(hugeLen, sizeof(hugeLen), t));

    // 4. Missing EOC in indefinite form
    const uint8_t noEoc[] = {0x30, 0x80, 0x02, 0x01, 0x01};
    EXPECT_FALSE(readBerTlv(noEoc, sizeof(noEoc), t));

    // 5. Recursion depth limit (exceeding 32 levels)
    std::vector<uint8_t> nested;
    for (int i = 0; i < 35; ++i) {
        nested.push_back(0x30);
        nested.push_back(0x80); // indefinite sequence
    }
    for (int i = 0; i < 35; ++i) {
        nested.push_back(0x00);
        nested.push_back(0x00); // EOC
    }
    EXPECT_FALSE(readBerTlv(nested.data(), nested.size(), t, 32));
}

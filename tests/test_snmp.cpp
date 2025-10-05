#include <gtest/gtest.h>

#include <functional>
#include <random>

#include <filter/filter.h>

#include "support.h"

using support::hex;

namespace {
    std::string byteToHex(uint8_t b) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        return buf;
    }

    std::string tlv(uint8_t tag, const std::string &valHex) {
        const size_t len = valHex.size() / 2;
        std::string h = byteToHex(tag);
        if (len < 128) {
            h += byteToHex(static_cast<uint8_t>(len));
        } else if (len < 256) {
            h += "81" + byteToHex(static_cast<uint8_t>(len));
        } else {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "82%04x", static_cast<unsigned>(len));
            h += buf;
        }
        return h + valHex;
    }

    std::string bytes(const std::string &hexText) {
        auto v = hex(hexText);
        return std::string(v.begin(), v.end());
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        return r.ok && r.filter.matches(p);
    }

    void expectRangesInside(const packet::PacketInfo &p, size_t frameSize) {
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frameSize) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: p.fields) check(l);
    }

    packet::PacketInfo snmp(const std::string &hexPayload) {
        auto frame = support::udpPacket("0a000001", "0a000002", "8000", "00a1", bytes(hexPayload)); // 161 = 0x00a1
        auto p = support::parse(frame);
        expectRangesInside(p, frame.size());
        return p;
    }
} // namespace

TEST(Snmp, V1GetRequestSysDescr) {
    // 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    const std::string oidSysDescr = "2b06010201010100";
    const std::string varbind = tlv(0x30, tlv(0x06, oidSysDescr) + tlv(0x05, "")); // OID + NULL
    const std::string varbindList = tlv(0x30, varbind);
    const std::string pdu = tlv(0xa0, tlv(0x02, "000004d2") + tlv(0x02, "00") + tlv(0x02, "00") + varbindList); // req-id 1234, err 0, idx 0
    const std::string msg = tlv(0x30, tlv(0x02, "00") + tlv(0x04, "7075626c6963") + pdu); // v1, "public"

    const auto p = snmp(msg);
    EXPECT_EQ(p.protocol, "SNMP");
    EXPECT_EQ(p.info, "get-request sysDescr.0 (1.3.6.1.2.1.1.1.0)");
    EXPECT_NE(find(p.fields, "Simple Network Management Protocol"), nullptr);
    EXPECT_NE(find(p.fields, "version: v1 (0)"), nullptr);
    EXPECT_NE(find(p.fields, "community: public"), nullptr);
    EXPECT_NE(find(p.fields, "data: get-request (0)"), nullptr);
    EXPECT_NE(find(p.fields, "request-id: 1234"), nullptr);
    EXPECT_NE(find(p.fields, "error-status: noError (0)"), nullptr);
    EXPECT_NE(find(p.fields, "sysDescr.0 (1.3.6.1.2.1.1.1.0): NULL"), nullptr);

    EXPECT_TRUE(matches("snmp", p));
    EXPECT_TRUE(matches("snmp.version == 0", p));
    EXPECT_TRUE(matches("snmp.community == \"public\"", p));
    EXPECT_TRUE(matches("snmp.pdu_type == 0", p));
    EXPECT_TRUE(matches("snmp.request_id == 1234", p));
    EXPECT_TRUE(matches("snmp.error_status == 0", p));
    EXPECT_TRUE(matches("snmp.oid == \"1.3.6.1.2.1.1.1.0\"", p));
}

TEST(Snmp, V2cResponseMultipleVarbinds) {
    // sysDescr.0 = STRING: "imshark test host"
    const std::string vb1 = tlv(0x30, tlv(0x06, "2b06010201010100") + tlv(0x04, "696d736861726b207465737420686f7374"));
    // sysUpTime.0 = Timeticks: 12345 (123.45s) [Application 3]
    const std::string vb2 = tlv(0x30, tlv(0x06, "2b06010201010300") + tlv(0x43, "3039"));
    const std::string varbindList = tlv(0x30, vb1 + vb2);
    const std::string pdu = tlv(0xa2, tlv(0x02, "0000162e") + tlv(0x02, "00") + tlv(0x02, "00") + varbindList); // req-id 5678, err 0, idx 0
    const std::string msg = tlv(0x30, tlv(0x02, "01") + tlv(0x04, "70726976617465") + pdu); // v2c, "private"

    const auto p = snmp(msg);
    EXPECT_EQ(p.protocol, "SNMP");
    EXPECT_EQ(p.info, "response sysDescr.0 (1.3.6.1.2.1.1.1.0)");
    EXPECT_NE(find(p.fields, "version: v2c (1)"), nullptr);
    EXPECT_NE(find(p.fields, "community: private"), nullptr);
    EXPECT_NE(find(p.fields, "request-id: 5678"), nullptr);
    EXPECT_NE(find(p.fields, "sysDescr.0 (1.3.6.1.2.1.1.1.0): STRING: \"imshark test host\""), nullptr);
    EXPECT_NE(find(p.fields, "sysUpTime.0 (1.3.6.1.2.1.1.3.0): Timeticks: 12345 (123.45s)"), nullptr);

    EXPECT_TRUE(matches("snmp.version == 1", p));
    EXPECT_TRUE(matches("snmp.community == \"private\"", p));
    EXPECT_TRUE(matches("snmp.pdu_type == 2", p));
    EXPECT_TRUE(matches("snmp.request_id == 5678", p));
}

TEST(Snmp, V2cGetBulkRequest) {
    // ifDescr = 1.3.6.1.2.1.2
    const std::string vb = tlv(0x30, tlv(0x06, "2b0601020102") + tlv(0x05, ""));
    const std::string varbindList = tlv(0x30, vb);
    const std::string pdu = tlv(0xa5, tlv(0x02, "03e8") + tlv(0x02, "01") + tlv(0x02, "0a") + varbindList); // req-id 1000, non-rep 1, max-rep 10
    const std::string msg = tlv(0x30, tlv(0x02, "01") + tlv(0x04, "7075626c6963") + pdu); // v2c, "public"

    const auto p = snmp(msg);
    EXPECT_EQ(p.protocol, "SNMP");
    EXPECT_EQ(p.info, "get-bulk-request 1.3.6.1.2.1.2");
    EXPECT_NE(find(p.fields, "non-repeaters: 1"), nullptr);
    EXPECT_NE(find(p.fields, "max-repetitions: 10"), nullptr);
    EXPECT_TRUE(matches("snmp.pdu_type == 5", p));
}

TEST(Snmp, V1Trap) {
    // enterprise: 1.3.6.1.4.1.8072 (net-snmp), agent-addr: 192.168.1.1, coldStart(0), spec 0, time 200
    const std::string pdu = tlv(0xa4, tlv(0x06, "2b06010401bf08") + tlv(0x40, "c0a80101") + tlv(0x02, "00") + tlv(0x02, "00") + tlv(0x43, "c8") + tlv(0x30, ""));
    const std::string msg = tlv(0x30, tlv(0x02, "00") + tlv(0x04, "7075626c6963") + pdu); // v1, "public"

    const auto p = snmp(msg);
    EXPECT_EQ(p.protocol, "SNMP");
    EXPECT_EQ(p.info, "trap coldStart enterprise=1.3.6.1.4.1.8072");
    EXPECT_NE(find(p.fields, "generic-trap: coldStart (0)"), nullptr);
    EXPECT_NE(find(p.fields, "agent-addr: 192.168.1.1"), nullptr);
    EXPECT_TRUE(matches("snmp.pdu_type == 4", p));
}

TEST(Snmp, V2cErrorResponse) {
    const std::string vb = tlv(0x30, tlv(0x06, "2b0601") + tlv(0x05, ""));
    const std::string pdu = tlv(0xa2, tlv(0x02, "0001") + tlv(0x02, "02") + tlv(0x02, "01") + tlv(0x30, vb)); // req-id 1, error 2 (noSuchName), index 1
    const std::string msg = tlv(0x30, tlv(0x02, "01") + tlv(0x04, "7075626c6963") + pdu);

    const auto p = snmp(msg);
    EXPECT_EQ(p.info, "response error: noSuchName at index 1");
    EXPECT_NE(find(p.fields, "error-status: noSuchName (2)"), nullptr);
    EXPECT_TRUE(matches("snmp.error_status == 2", p));
}

TEST(Snmp, V3EncryptedPdu) {
    // msgGlobalData: msgID 1001, msgMaxSize 1500, msgFlags 0x03, msgSecurityModel 3
    const std::string globalData = tlv(0x30, tlv(0x02, "03e9") + tlv(0x02, "05dc") + tlv(0x04, "03") + tlv(0x02, "03"));
    // USM: engineID 01020304, boots 1, time 10, user "alice" (616c696365)
    const std::string usm = tlv(0x30, tlv(0x04, "01020304") + tlv(0x02, "01") + tlv(0x02, "0a") + tlv(0x04, "616c696365") + tlv(0x04, "") + tlv(0x04, ""));
    const std::string secParams = tlv(0x04, bytes(usm));
    const std::string encPayload = tlv(0x04, "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4");
    const std::string msg = tlv(0x30, tlv(0x02, "03") + globalData + tlv(0x04, usm) + encPayload);

    const auto p = snmp(msg);
    EXPECT_EQ(p.protocol, "SNMP");
    EXPECT_EQ(p.info, "SNMPv3 encrypted PDU (user: alice)");
    EXPECT_NE(find(p.fields, "[ScopedPDU encrypted - not decrypted]"), nullptr);
    EXPECT_NE(find(p.fields, "msgUserName: alice"), nullptr);
    EXPECT_TRUE(matches("snmp.version == 3", p));
    EXPECT_TRUE(matches("snmp.community == \"alice\"", p));
}

TEST(Snmp, SurviveDamageAndMalformedInputs) {
    std::mt19937 rng(42);
    const std::string seed =
        "3029"
          "020100"
          "04067075626c6963"
          "a01c"
            "0204000004d2"
            "020100"
            "020100"
            "300e"
              "300c"
                "06082b06010201010100"
                "0500";

    for (int i = 0; i < 4000; ++i) {
        auto b = bytes(seed);
        b.resize(rng() % (b.size() + 1));
        for (unsigned k = rng() % 4; k > 0 && !b.empty(); --k) {
            b[rng() % b.size()] = static_cast<char>(rng());
        }
        auto frame = support::udpPacket("0a000001", "0a000002", "8000", "00a1", support::hexOf(b));
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        expectRangesInside(info, frame.size());
    }
}

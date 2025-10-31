#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parseEthernet(uint16_t etherType, const std::vector<uint8_t> &payload, bool pad = true) {
        packet::PacketInfo pack;
        pack.link_type = 1; // Ethernet
        std::vector<uint8_t> eth = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // DA
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // SA
            static_cast<uint8_t>(etherType >> 8), static_cast<uint8_t>(etherType & 0xff)
        };
        eth.insert(eth.end(), payload.begin(), payload.end());
        if (pad && eth.size() < 60) eth.resize(60, 0);

        std::vector<char> raw(eth.begin(), eth.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    bool matchFilter(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        return r.ok && r.filter.matches(p);
    }

    const packet::Field *findFieldRecursive(const packet::Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) {
            if (const auto *res = findFieldRecursive(c, prefix)) return res;
        }
        return nullptr;
    }

    const packet::Field *findLayer(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &f: p.fields) {
            if (const auto *res = findFieldRecursive(f, prefix)) return res;
        }
        return nullptr;
    }

    // LLDP TLV: 2-byte header (type: 7 bits, length: 9 bits) followed by the body.
    void appendLldpTlv(std::vector<uint8_t> &out, uint8_t type, const std::vector<uint8_t> &body) {
        const uint16_t length = static_cast<uint16_t>(body.size());
        out.push_back(static_cast<uint8_t>((type << 1) | ((length >> 8) & 0x01)));
        out.push_back(static_cast<uint8_t>(length & 0xFF));
        out.insert(out.end(), body.begin(), body.end());
    }

    std::vector<uint8_t> lldpDu() {
        std::vector<uint8_t> du;
        appendLldpTlv(du, 1, {4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); // Chassis ID, subtype 4 (MAC)
        appendLldpTlv(du, 2, {5, 'e', 't', 'h', '0'});                 // Port ID, subtype 5 (interface name)
        appendLldpTlv(du, 3, {0x00, 0x78});                            // TTL = 120
        appendLldpTlv(du, 5, {'i', 'm', 's', 'h', 'a', 'r', 'k', '-', 's', 'w'}); // System Name
        appendLldpTlv(du, 0, {});                                      // End of LLDPDU
        return du;
    }

    // LACP TLV: type byte + length byte (full TLV length, header included) + body.
    std::vector<uint8_t> lacpParticipant(uint16_t systemPriority, const std::vector<uint8_t> &system,
                                         uint16_t key, uint16_t portPriority, uint16_t port, uint8_t state) {
        std::vector<uint8_t> body = {
            static_cast<uint8_t>(systemPriority >> 8), static_cast<uint8_t>(systemPriority & 0xff)
        };
        body.insert(body.end(), system.begin(), system.end());
        body.push_back(static_cast<uint8_t>(key >> 8));
        body.push_back(static_cast<uint8_t>(key & 0xff));
        body.push_back(static_cast<uint8_t>(portPriority >> 8));
        body.push_back(static_cast<uint8_t>(portPriority & 0xff));
        body.push_back(static_cast<uint8_t>(port >> 8));
        body.push_back(static_cast<uint8_t>(port & 0xff));
        body.push_back(state);
        body.insert(body.end(), {0, 0, 0}); // reserved
        return body;
    }

    std::vector<uint8_t> lacpFrame() {
        std::vector<uint8_t> f = {0x01, 0x01}; // subtype LACP, version 1
        const std::vector<uint8_t> actor = lacpParticipant(0x8000, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, 0x00ff, 4, 0x3d);
        const std::vector<uint8_t> partner = lacpParticipant(0x8000, {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}, 2, 0x00ff, 8, 0x3d);
        f.push_back(1);
        f.push_back(static_cast<uint8_t>(actor.size() + 2));
        f.insert(f.end(), actor.begin(), actor.end());
        f.push_back(2);
        f.push_back(static_cast<uint8_t>(partner.size() + 2));
        f.insert(f.end(), partner.begin(), partner.end());
        f.push_back(0); // Terminator
        f.push_back(0);
        return f;
    }
} // namespace

TEST(LldpTest, ChassisPortTtlAndSysname) {
    const packet::PacketInfo p = parseEthernet(0x88CC, lldpDu());

    EXPECT_EQ(p.protocol, "LLDP");
    EXPECT_NE(p.info.find("imshark-sw"), std::string::npos);
    EXPECT_TRUE(matchFilter("lldp", p));
    EXPECT_TRUE(matchFilter("lldp.chassis_id == \"aa:bb:cc:dd:ee:ff\"", p));
    EXPECT_TRUE(matchFilter("lldp.port_id == \"eth0\"", p));
    EXPECT_TRUE(matchFilter("lldp.ttl == 120", p));
    EXPECT_TRUE(matchFilter("!lacp && !mac_control", p));
    ASSERT_NE(findLayer(p, "Link Layer Discovery Protocol"), nullptr);
    ASSERT_NE(findLayer(p, "System Name: imshark-sw"), nullptr);
}

TEST(LldpTest, TruncatedTlvDoesNotCrash) {
    EXPECT_TRUE(matchFilter("malformed", parseEthernet(0x88CC, {0x00}, false)));

    std::vector<uint8_t> overrun = {0x0a, 0x64, 'x', 'y'}; // System Name TLV claims 100 bytes, only 2 present
    EXPECT_TRUE(matchFilter("malformed", parseEthernet(0x88CC, overrun, false)));
}

TEST(LacpTest, ActorAndPartner) {
    const packet::PacketInfo p = parseEthernet(0x8809, lacpFrame());

    EXPECT_EQ(p.protocol, "LACP");
    EXPECT_TRUE(matchFilter("lacp", p));
    EXPECT_TRUE(matchFilter("lacp.actor.system == \"00:11:22:33:44:55\"", p));
    EXPECT_TRUE(matchFilter("lacp.partner.system == \"66:77:88:99:aa:bb\"", p));
    EXPECT_TRUE(matchFilter("lacp.actor.port == 4", p));
    EXPECT_TRUE(matchFilter("lacp.partner.port == 8", p));
    EXPECT_TRUE(matchFilter("lacp.actor.state == 0x3d", p));
    EXPECT_TRUE(matchFilter("lacp.actor.state.synchronization", p));
    EXPECT_TRUE(matchFilter("lacp.actor.state.distributing", p));
    EXPECT_TRUE(matchFilter("!lldp && !mac_control", p));
    ASSERT_NE(findLayer(p, "Link Aggregation Control Protocol"), nullptr);
}

TEST(LacpTest, TruncatedTlvDoesNotCrash) {
    EXPECT_TRUE(matchFilter("malformed", parseEthernet(0x8809, {0x01}, false)));

    std::vector<uint8_t> overrun = {0x01, 0x01, 0x01, 0x14, 0x00}; // Actor TLV claims 20 bytes, frame ends
    EXPECT_TRUE(matchFilter("malformed", parseEthernet(0x8809, overrun, false)));
}

TEST(MacControlTest, PauseFrame) {
    const packet::PacketInfo p = parseEthernet(0x8808, {0x00, 0x01, 0x00, 0x10});

    EXPECT_EQ(p.protocol, "MAC Control");
    EXPECT_NE(p.info.find("PAUSE"), std::string::npos);
    EXPECT_TRUE(matchFilter("mac_control", p));
    EXPECT_TRUE(matchFilter("mac_control.opcode == 0x0001", p));
    EXPECT_TRUE(matchFilter("pause", p));
    EXPECT_TRUE(matchFilter("pause.time == 16", p));
    EXPECT_TRUE(matchFilter("!pfc && !lldp && !lacp", p));
    ASSERT_NE(findLayer(p, "Ethernet MAC Control"), nullptr);
}

TEST(MacControlTest, PriorityFlowControl) {
    std::vector<uint8_t> payload = {0x01, 0x01, 0x00, 0x03};
    for (int i = 0; i < 8; ++i) {
        payload.push_back(0x00);
        payload.push_back(static_cast<uint8_t>(i + 1));
    }
    const packet::PacketInfo p = parseEthernet(0x8808, payload);

    EXPECT_EQ(p.protocol, "MAC Control");
    EXPECT_TRUE(matchFilter("pfc", p));
    EXPECT_TRUE(matchFilter("pfc.class_enable == 3", p));
    EXPECT_TRUE(matchFilter("mac_control.opcode == 0x0101", p));
    EXPECT_TRUE(matchFilter("!pause", p));
}

TEST(MacControlTest, TruncatedDoesNotCrash) {
    EXPECT_TRUE(matchFilter("malformed", parseEthernet(0x8808, {0x00}, false)));
}

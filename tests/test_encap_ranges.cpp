#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <packet/packet_info.h>
#include <packet/packet_parser.h>

// Byte ranges of the encapsulation layers (MPLS, IP-in-IP, GRE/ERSPAN, LLDP, LACP, MAC Control):
// hand-computed offsets for complete frames, and a truncation/mutation sweep that checks every
// field of the tree stays inside the captured frame.
namespace {
    packet::PacketInfo parseFrame(const std::vector<uint8_t> &frame) {
        packet::PacketInfo pack;
        pack.link_type = 1; // Ethernet
        std::vector<char> raw(frame.begin(), frame.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    std::vector<uint8_t> ethFrame(uint16_t type, const std::vector<uint8_t> &payload) {
        std::vector<uint8_t> e = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type & 0xff)
        };
        e.insert(e.end(), payload.begin(), payload.end());
        return e;
    }

    std::vector<uint8_t> ipv4(uint8_t protocol, const std::vector<uint8_t> &payload, uint8_t last) {
        const uint16_t total = static_cast<uint16_t>(20 + payload.size());
        std::vector<uint8_t> h = {
            0x45, 0x00, static_cast<uint8_t>(total >> 8), static_cast<uint8_t>(total & 0xff),
            0x00, 0x01, 0x00, 0x00, 0x40, protocol, 0x00, 0x00,
            10, 0, 0, 1, 10, 0, 0, last
        };
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

    std::vector<uint8_t> udp(const std::vector<uint8_t> &data) {
        const uint16_t len = static_cast<uint16_t>(8 + data.size());
        std::vector<uint8_t> h = {0x9c, 0x40, 0xc3, 0x50, static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len & 0xff), 0, 0};
        h.insert(h.end(), data.begin(), data.end());
        return h;
    }

    std::vector<uint8_t> gre(uint16_t flags, uint16_t proto, const std::vector<uint8_t> &optional,
                             const std::vector<uint8_t> &payload) {
        std::vector<uint8_t> g = {
            static_cast<uint8_t>(flags >> 8), static_cast<uint8_t>(flags & 0xff),
            static_cast<uint8_t>(proto >> 8), static_cast<uint8_t>(proto & 0xff)
        };
        g.insert(g.end(), optional.begin(), optional.end());
        g.insert(g.end(), payload.begin(), payload.end());
        return g;
    }

    void appendLldpTlv(std::vector<uint8_t> &out, uint8_t type, const std::vector<uint8_t> &body) {
        out.push_back(static_cast<uint8_t>((type << 1) | ((body.size() >> 8) & 0x01)));
        out.push_back(static_cast<uint8_t>(body.size() & 0xFF));
        out.insert(out.end(), body.begin(), body.end());
    }

    std::vector<uint8_t> lacpParticipant(uint8_t tlvType, uint8_t systemLast, uint8_t state) {
        std::vector<uint8_t> t = {tlvType, 20, 0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, systemLast,
                                  0x00, 0x01, 0x00, 0xff, 0x00, 0x04, state, 0, 0, 0};
        return t;
    }

    const packet::Field *findField(const packet::Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) {
            if (const auto *res = findField(c, prefix)) return res;
        }
        return nullptr;
    }

    const packet::Field *findLayer(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &f: p.fields) {
            if (const auto *res = findField(f, prefix)) return res;
        }
        return nullptr;
    }

    // Every node of the tree must lie inside the frame.
    bool inside(const packet::Field &f, size_t frameSize) {
        if (size_t(f.offset) + f.length > frameSize) return false;
        for (const auto &c: f.children) {
            if (!inside(c, frameSize)) return false;
        }
        return true;
    }

    void expectRange(const packet::PacketInfo &p, const std::string &prefix, uint32_t offset, uint32_t length) {
        const packet::Field *f = findLayer(p, prefix);
        ASSERT_NE(f, nullptr) << prefix;
        EXPECT_EQ(f->offset, offset) << prefix;
        EXPECT_EQ(f->length, length) << prefix;
    }

    std::vector<std::vector<uint8_t>> encapsulatedFrames() {
        const auto innerUdp = ipv4(17, udp({0x11, 0x22, 0x33, 0x44}), 2);
        std::vector<std::vector<uint8_t>> frames;

        // MPLS: two labels (the first without bottom of stack) over IPv4/UDP.
        std::vector<uint8_t> mpls = {0x00, 0x06, 0x40, 0x40, 0x00, 0x0c, 0x81, 0x3f};
        mpls.insert(mpls.end(), innerUdp.begin(), innerUdp.end());
        frames.push_back(ethFrame(0x8847, mpls));

        // IP-in-IP and GRE (C|K|S) over IPv4.
        frames.push_back(ethFrame(0x0800, ipv4(4, innerUdp, 9)));
        const std::vector<uint8_t> greOptional = {0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x07};
        frames.push_back(ethFrame(0x0800, ipv4(47, gre(0xB000, 0x0800, greOptional, innerUdp), 9)));

        // ERSPAN Type II mirroring an Ethernet frame.
        std::vector<uint8_t> erspan = {0x10, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
        const auto mirrored = ethFrame(0x0800, innerUdp);
        erspan.insert(erspan.end(), mirrored.begin(), mirrored.end());
        frames.push_back(ethFrame(0x0800, ipv4(47, gre(0x1000, 0x88BE, {0, 0, 0, 1}, erspan), 9)));

        // LLDP, LACP, PAUSE and PFC.
        std::vector<uint8_t> lldp;
        appendLldpTlv(lldp, 1, {4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff});
        appendLldpTlv(lldp, 2, {5, 'e', 't', 'h', '0'});
        appendLldpTlv(lldp, 3, {0x00, 0x78});
        appendLldpTlv(lldp, 5, {'s', 'w'});
        appendLldpTlv(lldp, 0, {});
        frames.push_back(ethFrame(0x88CC, lldp));

        std::vector<uint8_t> lacp = {0x01, 0x01};
        const auto actor = lacpParticipant(1, 0x55, 0x3d);
        const auto partner = lacpParticipant(2, 0x66, 0x3d);
        lacp.insert(lacp.end(), actor.begin(), actor.end());
        lacp.insert(lacp.end(), partner.begin(), partner.end());
        lacp.insert(lacp.end(), {0, 0});
        frames.push_back(ethFrame(0x8809, lacp));

        frames.push_back(ethFrame(0x8808, {0x00, 0x01, 0x00, 0x10}));
        std::vector<uint8_t> pfc = {0x01, 0x01, 0x00, 0x03};
        for (int i = 0; i < 8; ++i) pfc.insert(pfc.end(), {0x00, static_cast<uint8_t>(i + 1)});
        frames.push_back(ethFrame(0x8808, pfc));
        return frames;
    }
} // namespace

TEST(EncapsulationRanges, MplsLabelStackEntries) {
    const auto frames = encapsulatedFrames();
    const packet::PacketInfo p = parseFrame(frames[0]);
    ASSERT_EQ(p.protocol, "UDP");
    // Two 4-byte stack entries start right after the 14-byte Ethernet header.
    const packet::Field *first = findLayer(p, "MultiProtocol Label Switching Header, Label: 100,");
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->offset, 14u);
    EXPECT_EQ(first->length, 4u);
    const packet::Field *second = findLayer(p, "MultiProtocol Label Switching Header, Label: 200,");
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second->offset, 18u);
    EXPECT_EQ(second->length, 4u);
    // The inner IPv4 header begins after the stack: Ethernet 14 + 2 * 4.
    EXPECT_EQ(p.source, "10.0.0.1");
}

TEST(EncapsulationRanges, GreHeaderCoversOptionalFields) {
    const auto frames = encapsulatedFrames();
    const packet::PacketInfo p = parseFrame(frames[2]);
    ASSERT_EQ(p.protocol, "UDP");
    // Outer Ethernet 14 + IPv4 20 = 34; GRE header 4 + checksum/offset 4 + key 4 + sequence 4.
    expectRange(p, "Generic Routing Encapsulation", 34, 16);
    expectRange(p, "Protocol Type", 36, 2);
    expectRange(p, "Checksum:", 38, 2);
    expectRange(p, "Key:", 42, 4);
    expectRange(p, "Sequence Number:", 46, 4);
}

TEST(EncapsulationRanges, ErspanHeaderPrecedesMirroredFrame) {
    const auto frames = encapsulatedFrames();
    const packet::PacketInfo p = parseFrame(frames[3]);
    ASSERT_EQ(p.protocol, "UDP");
    // GRE: 34 + 4 header + 4 sequence = 42; ERSPAN Type II header is 8 bytes.
    expectRange(p, "Generic Routing Encapsulation", 34, 8);
    expectRange(p, "ERSPAN Type II", 42, 8);
}

TEST(EncapsulationRanges, ControlProtocolsCoverTheirPayload) {
    const auto frames = encapsulatedFrames();
    const packet::PacketInfo lldp = parseFrame(frames[4]);
    ASSERT_EQ(lldp.protocol, "LLDP");
    expectRange(lldp, "Link Layer Discovery Protocol", 14, uint32_t(frames[4].size() - 14));
    expectRange(lldp, "Chassis ID", 14, 9);
    expectRange(lldp, "Port ID", 23, 7);
    expectRange(lldp, "Time To Live", 30, 4);

    const packet::PacketInfo lacp = parseFrame(frames[5]);
    ASSERT_EQ(lacp.protocol, "LACP");
    expectRange(lacp, "Link Aggregation Control Protocol", 14, uint32_t(frames[5].size() - 14));

    const packet::PacketInfo pause = parseFrame(frames[6]);
    ASSERT_EQ(pause.protocol, "MAC Control");
    expectRange(pause, "Opcode: PAUSE", 14, 2);
    expectRange(pause, "Pause Time", 16, 2);

    const packet::PacketInfo pfc = parseFrame(frames[7]);
    expectRange(pfc, "Opcode: Priority Flow Control", 14, 2);
    expectRange(pfc, "Class Enable Vector", 16, 2);
}

TEST(EncapsulationRanges, TruncationAndMutationStayInsideFrame) {
    uint32_t seed = 0x1badb002u;
    auto next = [&seed]() {
        seed = seed * 1664525u + 1013904223u;
        return seed >> 8;
    };
    for (const auto &frame: encapsulatedFrames()) {
        // Complete frame and every truncation of it.
        for (size_t n = 0; n <= frame.size(); ++n) {
            const std::vector<uint8_t> cut(frame.begin(), frame.begin() + n);
            const packet::PacketInfo p = parseFrame(cut);
            for (const auto &f: p.fields) EXPECT_TRUE(inside(f, n)) << "truncated to " << n << ": " << f.text;
        }
        // Random byte mutations (header bytes included) at full and truncated sizes.
        for (int round = 0; round < 300; ++round) {
            std::vector<uint8_t> mutated = frame;
            const int flips = 1 + int(next() % 3);
            for (int i = 0; i < flips; ++i) mutated[next() % mutated.size()] = static_cast<uint8_t>(next());
            mutated.resize(next() % (mutated.size() + 1));
            const packet::PacketInfo p = parseFrame(mutated);
            for (const auto &f: p.fields) EXPECT_TRUE(inside(f, mutated.size())) << "mutation round " << round << ": " << f.text;
        }
    }
}

#include <gtest/gtest.h>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "frame_sweep.h"
#include "support.h"

using support::hex;
using support::parse;

namespace {
    // Helper to wrap IGMP inside IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=224.0.0.1, proto=2
    std::vector<char> makeIgmpPacket(const std::vector<uint8_t> &igmpPayload) {
        // Ethernet header: dst=01:00:5e:00:00:01, src=00:11:22:33:44:55, etype=0x0800
        std::vector<uint8_t> frame = {
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x01,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00
        };

        // IPv4 header (20 bytes): len = 20 + payload.size(), proto = 2
        uint16_t ipTotalLen = static_cast<uint16_t>(20 + igmpPayload.size());
        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            0x01, 0x02, 0x00, 0x00, // TTL=1, proto=2 (IGMP), zero csum placeholder
            10, 0, 0, 1,            // src 10.0.0.1
            224, 0, 0, 1            // dst 224.0.0.1
        };

        // Calculate IPv4 checksum
        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) {
            csum += (ip[i] << 8) | ip[i + 1];
        }
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), igmpPayload.begin(), igmpPayload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Igmp, GeneralMembershipQuery) {
    // IGMPv2 Query (type=0x11, max_resp_time=100 (10.0s), group=0.0.0.0)
    // Checksum = ~sum(0x1164 + 0x0000 + 0x0000 + 0x0000) = ~0x1164 = 0xEE9B
    std::vector<uint8_t> payload = {
        0x11, 0x64, 0xee, 0x9b,
        0x00, 0x00, 0x00, 0x00
    };

    auto pkt = parse(makeIgmpPacket(payload));
    EXPECT_EQ(pkt.protocol, "IGMP");
    EXPECT_EQ(pkt.info, "General Membership Query");
    EXPECT_EQ(pkt.app_type, 0x11);
    EXPECT_EQ(pkt.app_code, 100);
    EXPECT_EQ(pkt.app_text, "0.0.0.0");

    // Check filter matching
    auto f = filter::Filter::compile("igmp && igmp.type == 0x11");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Igmp, MembershipReportV2) {
    // IGMPv2 Report (type=0x16, max_resp_time=0, group=224.1.2.3)
    // 0x1600 + csum + 0xe001 + 0x0203
    // Sum = 0x1600 + 0xe001 + 0x0203 = 0xF804 -> csum = 0x07FB
    std::vector<uint8_t> payload = {
        0x16, 0x00, 0x07, 0xfb,
        224, 1, 2, 3
    };

    auto pkt = parse(makeIgmpPacket(payload));
    EXPECT_EQ(pkt.protocol, "IGMP");
    EXPECT_EQ(pkt.info, "IGMPv2 Membership Report, group 224.1.2.3");
    EXPECT_EQ(pkt.app_type, 0x16);
    EXPECT_EQ(pkt.app_text, "224.1.2.3");

    auto f = filter::Filter::compile("igmp.group == \"224.1.2.3\"");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

namespace {
    using framesweep::Bytes;

    packet::PacketInfo igmpFrame(const Bytes &igmp, const Bytes &dst = {224, 0, 0, 251}) {
        return framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(2, igmp, {10, 0, 0, 1}, dst)));
    }
    uint8_t state(const packet::PacketInfo &p) { return dissect::transportChecksumState(p); }
} // namespace

// Checksums computed with Python (stdlib): cs(b) = ~(folded sum of the 16-bit words of b with the checksum zero) & 0xffff
//   v2 report 224.0.0.251: cs(16 00 00 00 e0 00 00 fb) = 0x0904     general query (mrt 100): 0xee9b
//   leave 224.0.0.251: 0x0804                                       v3 report, one record, one source: 0xe9f5
TEST(Igmp, ChecksumsMatchAnIndependentComputation) {
    EXPECT_EQ(state(igmpFrame({0x16, 0, 0x09, 0x04, 224, 0, 0, 251})), dissect::kChecksumGood);
    EXPECT_EQ(state(igmpFrame({0x16, 0, 0x09, 0x05, 224, 0, 0, 251})), dissect::kChecksumBad);
    EXPECT_EQ(state(igmpFrame({0x11, 0x64, 0xee, 0x9b, 0, 0, 0, 0}, {224, 0, 0, 1})), dissect::kChecksumGood);
    EXPECT_EQ(state(igmpFrame({0x17, 0, 0x08, 0x04, 224, 0, 0, 251}, {224, 0, 0, 2})), dissect::kChecksumGood);
    const auto v3 = igmpFrame({0x22, 0, 0xe9, 0xf5, 0, 0, 0, 1, 1, 0, 0, 1, 232, 1, 1, 1, 10, 0, 0, 5}, {224, 0, 0, 22});
    EXPECT_EQ(state(v3), dissect::kChecksumGood);
    EXPECT_EQ(v3.app_type, 0x22);
    EXPECT_NE(v3.info.find("1 group record"), std::string::npos) << v3.info;
}

namespace {
    const packet::Field *findNode(const std::vector<packet::Field> &nodes, const std::string &prefix) {
        for (const auto &n: nodes) {
            if (n.text.rfind(prefix, 0) == 0) return &n;
            if (auto *c = findNode(n.children, prefix)) return c;
        }
        return nullptr;
    }
    size_t countNodes(const std::vector<packet::Field> &nodes, const std::string &prefix) {
        size_t n = 0;
        for (const auto &f: nodes) n += (f.text.rfind(prefix, 0) == 0 ? 1 : 0) + countNodes(f.children, prefix);
        return n;
    }
    // counts inside the IGMP layer only (the IPv4 header has its own "Source Address")
    size_t countIgmpNodes(const packet::PacketInfo &p, const std::string &prefix) {
        const auto *layer = findNode(p.fields, "Internet Group Management Protocol");
        return layer ? countNodes(layer->children, prefix) : 0;
    }
    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr;
        return f.ok && f.filter.matches(p);
    }

    // RFC 3376 4.1: general query (QRV 2, QQIC 125), checksums from stdlib Python (one's complement sum of the 16-bit words
    // with the checksum zero, folded and inverted): 0xec1e
    const Bytes queryV3General = {0x11, 0x64, 0xec, 0x1e, 0, 0, 0, 0, 0x02, 125, 0, 0};
    // group-and-source-specific query: group 232.1.1.1, S=1 QRV=2, Max Resp Code 0x91 (17 << 4 = 272 tenths), QQIC 0x8f (31 << 3 = 248 s),
    // sources 10.0.0.5 and 10.0.0.6: 0xe6cf
    const Bytes queryV3Sources = {0x11, 0x91, 0xe6, 0xcf, 232, 1, 1, 1, 0x0a, 0x8f, 0, 2, 10, 0, 0, 5, 10, 0, 0, 6};
    // report with three records (RFC 3376 4.2): MODE_IS_INCLUDE 232.1.1.1 with two sources, CHANGE_TO_EXCLUDE 224.1.1.1 with
    // four bytes of auxiliary data, MODE_IS_EXCLUDE 224.9.9.9 without sources: 0x7238
    const Bytes reportV3 = {0x22, 0, 0x72, 0x38, 0, 0, 0, 3,
                            1, 0, 0, 2, 232, 1, 1, 1, 10, 0, 0, 5, 10, 0, 0, 6,
                            4, 1, 0, 0, 224, 1, 1, 1, 0xde, 0xad, 0xbe, 0xef,
                            2, 0, 0, 0, 224, 9, 9, 9};
} // namespace

TEST(Igmp, V3QueryDecodesFlagsQqicAndSourceList) {
    const auto g = igmpFrame(queryV3General, {224, 0, 0, 1});
    EXPECT_EQ(state(g), dissect::kChecksumGood);
    EXPECT_EQ(g.info, "General Membership Query");
    EXPECT_TRUE(matches("igmp.version == 3 && igmp.num_sources == 0", g));
    EXPECT_NE(findNode(g.fields, "Flags: 0x02 (S=0, QRV=2)"), nullptr);
    EXPECT_NE(findNode(g.fields, "QQIC: 125 sec (125)"), nullptr);

    const auto s = igmpFrame(queryV3Sources, {232, 1, 1, 1});
    EXPECT_EQ(state(s), dissect::kChecksumGood);
    EXPECT_EQ(s.info, "Group-Specific Query, group 232.1.1.1, 2 source(s)");
    EXPECT_TRUE(matches("igmp.version == 3 && igmp.num_sources == 2 && igmp.group == \"232.1.1.1\"", s));
    EXPECT_NE(findNode(s.fields, "Flags: 0x0a (S=1, QRV=2)"), nullptr);
    EXPECT_NE(findNode(s.fields, "QQIC: 248 sec (143)"), nullptr);          // 0x8f: (15 | 0x10) << 3
    EXPECT_NE(findNode(s.fields, "Max Response Time: 27.200000 sec (145)"), nullptr);   // 0x91: (1 | 0x10) << 4 = 272 tenths
    EXPECT_NE(findNode(s.fields, "Source Address: 10.0.0.6"), nullptr);
    EXPECT_EQ(countIgmpNodes(s, "Source Address"), 2u);
    EXPECT_EQ(s.info.find("Malformed"), std::string::npos);

    // v2 (8 bytes) keeps its meaning; Max Resp Code 0 is v1
    EXPECT_TRUE(matches("igmp.version == 2", igmpFrame({0x11, 0x64, 0xee, 0x9b, 0, 0, 0, 0}, {224, 0, 0, 1})));
    EXPECT_TRUE(matches("igmp.version == 1", igmpFrame({0x11, 0x00, 0xee, 0xff, 0, 0, 0, 0}, {224, 0, 0, 1})));
    EXPECT_TRUE(matches("igmp.version == 1", igmpFrame({0x12, 0, 0, 0, 224, 1, 2, 3})));
    EXPECT_TRUE(matches("igmp.version == 2", igmpFrame({0x16, 0, 0x07, 0xfb, 224, 1, 2, 3})));
}

TEST(Igmp, V3QuerySourceCountBeyondTheMessageIsFlagged) {
    Bytes b = queryV3Sources;
    b[11] = 3;   // three sources announced, two present
    auto p = igmpFrame(b, {232, 1, 1, 1});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    EXPECT_EQ(countIgmpNodes(p, "Source Address"), 2u);
    framesweep::expectInside(p, 14 + 20 + b.size(), "query sources");
    b[10] = 0xff;   // 65 000+ sources
    p = igmpFrame(b, {232, 1, 1, 1});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    // 9..11 bytes are no valid query length
    p = igmpFrame(Bytes(queryV3General.begin(), queryV3General.begin() + 10), {224, 0, 0, 1});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
}

TEST(Igmp, V3ReportDecodesGroupRecordsAndSources) {
    const auto p = igmpFrame(reportV3, {224, 0, 0, 22});
    EXPECT_EQ(state(p), dissect::kChecksumGood);
    EXPECT_EQ(p.info, "IGMPv3 Membership Report, 3 group record(s)");
    EXPECT_TRUE(matches("igmp.version == 3 && igmp.num_records == 3", p));
    EXPECT_NE(findNode(p.fields, "Group Record: MODE_IS_INCLUDE 232.1.1.1"), nullptr);
    EXPECT_NE(findNode(p.fields, "Group Record: CHANGE_TO_EXCLUDE_MODE 224.1.1.1"), nullptr);
    EXPECT_NE(findNode(p.fields, "Group Record: MODE_IS_EXCLUDE 224.9.9.9"), nullptr);
    EXPECT_NE(findNode(p.fields, "Auxiliary Data (4 bytes)"), nullptr);
    EXPECT_EQ(countIgmpNodes(p, "Source Address"), 2u);
    EXPECT_EQ(p.info.find("Malformed"), std::string::npos);
    // the reserved/count bytes of the header are not a group address any more
    EXPECT_FALSE(matches("igmp.group == \"0.0.0.3\"", p));
    // the record starts at the right place: the aux data is the 4 bytes at message offset 32
    const auto *aux = findNode(p.fields, "Auxiliary Data");
    ASSERT_NE(aux, nullptr);
    EXPECT_EQ(aux->offset, 14u + 20u + 32u);
    EXPECT_EQ(aux->length, 4u);
}

TEST(Igmp, V3ReportCountsBeyondTheMessageAreFlagged) {
    // more records announced than present
    Bytes few = reportV3;
    few[7] = 4;
    auto p = igmpFrame(few, {224, 0, 0, 22});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    framesweep::expectInside(p, 14 + 20 + few.size(), "record count");
    // a source count that runs past the end: the record is cut at the message end
    Bytes src = reportV3;
    src[10] = 0x10;
    p = igmpFrame(src, {224, 0, 0, 22});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    framesweep::expectInside(p, 14 + 20 + src.size(), "source count");
    // an aux data length (255 words) that runs past the end
    Bytes aux = reportV3;
    aux[8 + 1] = 0xff;
    p = igmpFrame(aux, {224, 0, 0, 22});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    framesweep::expectInside(p, 14 + 20 + aux.size(), "aux length");
    // 65535 records in a header-only report
    p = igmpFrame({0x22, 0, 0, 0, 0, 0, 0xff, 0xff}, {224, 0, 0, 22});
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
}

TEST(Igmp, TruncationAndMutationStayInsideTheFrame) {
    const Bytes v3 = {0x22, 0, 0xe9, 0xf5, 0, 0, 0, 1, 1, 0, 0, 1, 232, 1, 1, 1, 10, 0, 0, 5};
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(2, v3, {10, 0, 0, 1}, {224, 0, 0, 22})), 0x16f00001u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(2, {0x16, 0, 0x09, 0x04, 224, 0, 0, 251})), 0x16f00002u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(2, reportV3, {10, 0, 0, 1}, {224, 0, 0, 22})), 0x16f00003u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(2, queryV3Sources, {10, 0, 0, 1}, {232, 1, 1, 1})), 0x16f00004u);
}

TEST(Igmp, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"IGMP"});
}

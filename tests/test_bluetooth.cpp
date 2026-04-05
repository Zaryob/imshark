#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/bluetooth.h>
#include "support.h"
#include "frame_sweep.h"

using support::parse;
using namespace dissect;
using framesweep::Bytes;

namespace {

packet::PacketInfo parseLinkPacket(uint32_t linkType, const std::vector<uint8_t> &data,
                                   dissect::ParseMode mode = dissect::ParseMode::Full) {
    return framesweep::parseEthernet(data, linkType, mode);
}

// Opcode 0x200C (LE Set Scan Enable) packs OGF 0x08 into bits 15..10 and OCF 0x00C into bits 9..0:
// python3 -c "op=0x200c; print(hex(op>>10), hex(op&0x3ff))"  ->  0x8 0xc
const Bytes kCommand = {0x0c, 0x20, 0x02, 0x01, 0x00};   // opcode (LE), parameter length 2, two parameter bytes

// HCI ACL: handle 0x0040, PB=0, BC=0, data length 7, L2CAP length 3, CID 4 (ATT), Exchange MTU Request 512
const Bytes kAclAtt = {0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02};

Bytes cat(Bytes a, const Bytes &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// The pcap pseudo header of LINKTYPE_BLUETOOTH_LINUX_MONITOR: adapter id and opcode, big endian
Bytes monitor(uint16_t adapter, uint16_t opcode, const Bytes &payload) {
    Bytes b = {static_cast<uint8_t>(adapter >> 8), static_cast<uint8_t>(adapter & 0xff), static_cast<uint8_t>(opcode >> 8),
               static_cast<uint8_t>(opcode & 0xff)};
    return cat(b, payload);
}

const packet::Field *find(const std::vector<packet::Field> &nodes, const std::string &prefix) {
    for (const auto &n: nodes) {
        if (n.text.rfind(prefix, 0) == 0) return &n;
        if (auto *c = find(n.children, prefix)) return c;
    }
    return nullptr;
}

} // namespace

TEST(Bluetooth, HciH4CommandPacket) {
    const auto pkt = parseLinkPacket(187, cat({0x01}, kCommand));

    EXPECT_EQ(pkt.protocol, "HCI");
    EXPECT_EQ(pkt.app_type, 1);
    EXPECT_EQ(pkt.info, "HCI Command: OGF 0x08, OCF 0x00c");
    EXPECT_EQ(pkt.source, "host");
    EXPECT_EQ(pkt.destination, "controller");
    // the opcode sits at frame bytes 1..2 (after the H4 indicator), the parameter length at byte 3
    const auto *opcode = find(pkt.fields, "Opcode: 0x200c");
    ASSERT_NE(opcode, nullptr);
    EXPECT_EQ(opcode->offset, 1u);
    EXPECT_EQ(opcode->length, 2u);
    const auto *plen = find(pkt.fields, "Parameter Length: 2");
    ASSERT_NE(plen, nullptr);
    EXPECT_EQ(plen->offset, 3u);
}

TEST(Bluetooth, HciH4EventPacket) {
    // Command Complete (0x0e), 4 parameter bytes: number of commands 1, opcode 0x0c03, status 0
    const auto pkt = parseLinkPacket(187, {0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00});

    EXPECT_EQ(pkt.protocol, "HCI");
    EXPECT_EQ(pkt.app_type, 4);
    EXPECT_EQ(pkt.info, "HCI Event: Command Complete");
    EXPECT_EQ(pkt.source, "controller");
    EXPECT_EQ(pkt.destination, "host");
}

TEST(Bluetooth, HciH4AclWithL2capAttExchangeMtu) {
    const auto pkt = parseLinkPacket(187, cat({0x02}, kAclAtt));

    EXPECT_EQ(pkt.protocol, "ATT");
    EXPECT_EQ(pkt.info, "ATT Exchange MTU Request (MTU: 512)");
    // the connection handle names the remote device
    EXPECT_EQ(pkt.source, "host");
    EXPECT_EQ(pkt.destination, "0x0040");
    framesweep::expectInside(pkt, 12, "ACL/ATT");
}

TEST(Bluetooth, LinuxMonitorUsesTheFourByteBigEndianPseudoHeader) {
    // adapter 1, opcode 2 (command packet), then the HCI command WITHOUT an H4 indicator
    const auto frame = monitor(1, 2, kCommand);
    const auto pkt = parseLinkPacket(254, frame);

    EXPECT_EQ(pkt.protocol, "HCI");
    EXPECT_EQ(pkt.app_type, 1);
    EXPECT_EQ(pkt.info, "HCI Command: OGF 0x08, OCF 0x00c");
    EXPECT_EQ(pkt.source, "host");
    EXPECT_EQ(pkt.destination, "hci1");
    const auto *adapter = find(pkt.fields, "Adapter ID: 1");
    ASSERT_NE(adapter, nullptr);
    EXPECT_EQ(adapter->offset, 0u);
    EXPECT_EQ(adapter->length, 2u);
    // the opcode of the HCI command is at frame bytes 4..5: every offset is a position in the frame
    const auto *opcode = find(pkt.fields, "Opcode: 0x200c");
    ASSERT_NE(opcode, nullptr);
    EXPECT_EQ(opcode->offset, 4u);
    EXPECT_EQ(opcode->length, 2u);
    framesweep::expectInside(pkt, frame.size(), "monitor command");
}

TEST(Bluetooth, LinuxMonitorAclDirectionComesFromTheOpcode) {
    const auto rx = parseLinkPacket(254, monitor(0, 5, kAclAtt));  // opcode 5: ACL RX
    EXPECT_EQ(rx.protocol, "ATT");
    EXPECT_EQ(rx.source, "0x0040");
    EXPECT_EQ(rx.destination, "host");
    const auto tx = parseLinkPacket(254, monitor(0, 4, kAclAtt));  // opcode 4: ACL TX
    EXPECT_EQ(tx.source, "host");
    EXPECT_EQ(tx.destination, "0x0040");

    const auto ev = parseLinkPacket(254, monitor(2, 3, {0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00}));
    EXPECT_EQ(ev.info, "HCI Event: Command Complete");
    EXPECT_EQ(ev.source, "hci2");
    EXPECT_EQ(ev.destination, "host");

    // other monitor opcodes carry no HCI packet: the header is all there is
    const auto idx = parseLinkPacket(254, monitor(3, 0, {1, 2, 3}));
    EXPECT_EQ(idx.protocol, "BT Mon");
    EXPECT_EQ(idx.info, "BT Mon hci3 New Index");
}

TEST(Bluetooth, ContinuationFragmentsAreNotL2capStarts) {
    // PB flag 1 (continuing fragment) in bits 13..12 of the handle word: 0x1040
    const Bytes frag = {0x02, 0x40, 0x10, 0x04, 0x00, 0x04, 0x00, 0x02, 0x00};
    const auto pkt = parseLinkPacket(187, frag);
    EXPECT_EQ(pkt.protocol, "L2CAP");
    EXPECT_EQ(pkt.info, "L2CAP Continuation Fragment (Handle 0x040, 4 bytes)");
    EXPECT_EQ(find(pkt.fields, "Bluetooth L2CAP ("), nullptr) << "the payload bytes are not an L2CAP header";
    EXPECT_NE(find(pkt.fields, "Bluetooth L2CAP Continuation Fragment"), nullptr);
    framesweep::expectInside(pkt, frag.size(), "continuation");
}

TEST(Bluetooth, DeclaredLengthsLargerThanTheDataAreMalformed) {
    // L2CAP length 0x0010 but only 3 bytes follow the header
    const auto l2cap = parseLinkPacket(187, {0x02, 0x40, 0x00, 0x07, 0x00, 0x10, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02});
    EXPECT_NE(l2cap.info.find("[Malformed Packet"), std::string::npos) << l2cap.info;
    EXPECT_EQ(l2cap.protocol, "ATT");
    // ACL data length 0x0040 with 7 bytes present
    const auto acl = parseLinkPacket(187, {0x02, 0x40, 0x00, 0x40, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02});
    EXPECT_NE(acl.info.find("[Malformed Packet"), std::string::npos) << acl.info;
    // command parameter length 9 with 2 bytes present
    const auto cmd = parseLinkPacket(187, {0x01, 0x0c, 0x20, 0x09, 0x01, 0x00});
    EXPECT_NE(cmd.info.find("[Malformed Packet"), std::string::npos) << cmd.info;
    // a header cut short
    EXPECT_NE(parseLinkPacket(187, {0x01, 0x0c}).info.find("[Malformed Packet"), std::string::npos);
    EXPECT_NE(parseLinkPacket(254, {0x00, 0x01, 0x00}).info.find("[Malformed Packet"), std::string::npos);
}

TEST(Bluetooth, TheInfoColumnDoesNotDependOnTheFieldTree) {
    for (const Bytes &frame: {cat({0x02}, kAclAtt), Bytes{0x02, 0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x1b, 0x2a, 0x00},
                              Bytes{0x02, 0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x17, 0x00}}) {
        const auto summary = parseLinkPacket(187, frame, dissect::ParseMode::Summary);
        const auto full = parseLinkPacket(187, frame, dissect::ParseMode::Full);
        EXPECT_EQ(summary.info, full.info);
        EXPECT_EQ(summary.protocol, full.protocol);
    }
    // a notification names its handle, a response its server MTU
    EXPECT_EQ(parseLinkPacket(187, {0x02, 0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x1b, 0x2a, 0x00}, dissect::ParseMode::Summary).info,
              "ATT Handle Value Notification Handle: 0x002a");
    EXPECT_EQ(parseLinkPacket(187, {0x02, 0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x17, 0x00}, dissect::ParseMode::Summary).info,
              "ATT Exchange MTU Response (MTU: 23)");
}

TEST(Bluetooth, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(cat({0x01}, kCommand), 11, 400, 187);
    framesweep::sweep({0x04, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00}, 12, 400, 187);
    framesweep::sweep(cat({0x02}, kAclAtt), 13, 400, 187);
    framesweep::sweep(monitor(1, 2, kCommand), 14, 400, 254);
    framesweep::sweep(monitor(0, 5, kAclAtt), 15, 400, 254);
    framesweep::sweep(monitor(0, 3, {0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00}), 16, 400, 254);
}

TEST(Bluetooth, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"HCI", "ATT", "L2CAP", "BT Mon"});
}

// ---- IEEE 802.15.4

TEST(Ieee802154, AcknowledgmentFrameWithFcs) {
    // LINKTYPE 195 (WITHFCS): FCF 0x0002 (type 2 = Acknowledgment), sequence 42, 2-byte FCS
    const Bytes frame = {0x02, 0x00, 42, 0xaa, 0xbb};
    const auto pkt = parseLinkPacket(195, frame);

    EXPECT_EQ(pkt.protocol, "802.15.4");
    EXPECT_EQ(pkt.app_type, 2);
    EXPECT_EQ(pkt.info, "Acknowledgment (Seq 42)");
    // the MAC layer ends before the FCS, which is its own node
    const auto *mac = find(pkt.fields, "IEEE 802.15.4 (");
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(mac->offset, 0u);
    EXPECT_EQ(mac->length, 3u);
    const auto *fcs = find(pkt.fields, "Frame Check Sequence: 0xbbaa");
    ASSERT_NE(fcs, nullptr);
    EXPECT_EQ(fcs->offset, 3u);
    EXPECT_EQ(fcs->length, 2u);
    // a 3 byte frame cannot hold the sequence number AND an FCS
    EXPECT_NE(parseLinkPacket(195, {0x02, 0x00, 42}).info.find("[Malformed Packet"), std::string::npos);
}

TEST(Ieee802154, FrameTypesFourToSevenFollowTheStandard) {
    // IEEE 802.15.4-2015 table 7-1
    const char *names[] = {"Beacon", "Data", "Acknowledgment", "MAC Command", "Reserved", "Multipurpose", "Fragment", "Extended"};
    for (int type = 0; type < 8; ++type) {
        const auto pkt = parseLinkPacket(230, {static_cast<uint8_t>(type), 0x00, 7});
        EXPECT_EQ(pkt.info, std::string(names[type]) + " (Seq 7)") << type;
        EXPECT_EQ(pkt.app_type, type);
    }
}

TEST(Ieee802154, NonAskPhyHeaderPrecedesTheMacFrame) {
    // preamble 00 00 00 00, SFD 0xA7, PHR: frame length 5 (MAC frame 3 bytes + FCS 2), then the MAC frame
    const Bytes frame = {0, 0, 0, 0, 0xa7, 0x05, 0x01, 0x00, 9, 0x12, 0x34};
    const auto pkt = parseLinkPacket(215, frame);
    EXPECT_EQ(pkt.protocol, "802.15.4");
    EXPECT_EQ(pkt.info, "Data (Seq 9)");
    const auto *phy = find(pkt.fields, "IEEE 802.15.4 PHY");
    ASSERT_NE(phy, nullptr);
    EXPECT_EQ(phy->length, 6u);
    const auto *sfd = find(pkt.fields, "Start of Frame Delimiter: 0xa7");
    ASSERT_NE(sfd, nullptr);
    EXPECT_EQ(sfd->offset, 4u);
    const auto *mac = find(pkt.fields, "IEEE 802.15.4 (Data)");
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(mac->offset, 6u);
    EXPECT_EQ(mac->length, 3u);
    EXPECT_NE(find(pkt.fields, "Frame Check Sequence: 0x3412"), nullptr);
    // a PHR that promises more than the capture holds
    EXPECT_NE(parseLinkPacket(215, {0, 0, 0, 0, 0xa7, 0x40, 0x01, 0x00, 9}).info.find("[Malformed Packet"), std::string::npos);
}

TEST(Ieee802154, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep({0x61, 0x88, 0x05, 0x34, 0x12, 0x78, 0x56, 0xaa, 0xbb}, 21, 400, 195);
    framesweep::sweep({0, 0, 0, 0, 0xa7, 0x05, 0x01, 0x00, 9, 0x12, 0x34}, 22, 400, 215);
    framesweep::sweep({0x05, 0x00, 1}, 23, 100, 230);
}

TEST(Ieee802154, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"802.15.4"});
}

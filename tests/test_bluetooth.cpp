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

// ---- BD_ADDR of ACL connections (B8): HCI connection events name the handle, later ACL packets show the address

namespace {
// Core spec Vol 4 Part E 7.7: the BD_ADDR is little endian on the wire; it is shown most significant byte first.
const Bytes kAddrA = {0x13, 0x71, 0xDA, 0x7D, 0x1A, 0x00};   // 00:1a:7d:da:71:13
const Bytes kAddrB = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};   // 11:22:33:44:55:66

Bytes aclFor(uint16_t handle) {
    Bytes b = kAclAtt;
    b[0] = static_cast<uint8_t>(handle & 0xff);
    b[1] = static_cast<uint8_t>(handle >> 8);
    return b;
}

// Connection Complete (0x03): status, handle (2), BD_ADDR (6), link type, encryption enabled
Bytes classicConnection(uint8_t status, uint16_t handle, const Bytes &addr) {
    Bytes b = {0x03, 0x0b, status, static_cast<uint8_t>(handle & 0xff), static_cast<uint8_t>(handle >> 8)};
    b.insert(b.end(), addr.begin(), addr.end());
    b.push_back(0x01);
    b.push_back(0x00);
    return b;
}

// LE Meta (0x3E), LE Connection Complete (0x01): subevent, status, handle (2), role, peer address type, peer address (6),
// interval (2), latency (2), supervision timeout (2), master clock accuracy
Bytes leConnection(uint16_t handle, const Bytes &addr) {
    Bytes b = {0x3e, 0x13, 0x01, 0x00, static_cast<uint8_t>(handle & 0xff), static_cast<uint8_t>(handle >> 8), 0x00, 0x00};
    b.insert(b.end(), addr.begin(), addr.end());
    for (int i = 0; i < 7; ++i) b.push_back(0);
    return b;
}

// LE Enhanced Connection Complete (0x0A): the same start, then local and peer resolvable private addresses, then the timing
Bytes leEnhancedConnection(uint16_t handle, const Bytes &addr) {
    Bytes b = {0x3e, 0x1f, 0x0a, 0x00, static_cast<uint8_t>(handle & 0xff), static_cast<uint8_t>(handle >> 8), 0x00, 0x00};
    b.insert(b.end(), addr.begin(), addr.end());
    for (int i = 0; i < 19; ++i) b.push_back(0);
    return b;
}

// Disconnection Complete (0x05): status, handle (2), reason
Bytes disconnection(uint16_t handle) {
    return {0x05, 0x04, 0x00, static_cast<uint8_t>(handle & 0xff), static_cast<uint8_t>(handle >> 8), 0x13};
}

Bytes h4(uint8_t indicator, const Bytes &rest) { return cat({indicator}, rest); }

struct Capture {
    packet::PacketParser parser;
    std::vector<packet::PacketInfo> packets;
    std::vector<Bytes> frames;
    uint32_t linkType;
    explicit Capture(uint32_t link, const std::vector<Bytes> &f) : frames(f), linkType(link) {
        int number = 1;
        for (const auto &fr: frames) {
            packet::PacketInfo pack(number++);
            pack.link_type = linkType;
            std::vector<char> raw(fr.begin(), fr.end());
            parser.parsePacket(pack, raw, dissect::ParseMode::Summary);
            packets.push_back(std::move(pack));
        }
    }
};
} // namespace

TEST(Bluetooth, ConnectionEventsNameTheAddressOfLaterAclPackets) {
    Capture c(187, {h4(2, aclFor(0x40)),                                  // 1 before any connection event: the handle
                    h4(4, classicConnection(0x00, 0x40, kAddrA)),         // 2
                    h4(2, aclFor(0x40)),                                  // 3 -> BD_ADDR A
                    h4(4, leConnection(0x41, kAddrB)),                    // 4
                    h4(2, aclFor(0x41)),                                  // 5 -> BD_ADDR B
                    h4(4, disconnection(0x40)),                           // 6
                    h4(2, aclFor(0x40)),                                  // 7 the handle is free again
                    h4(4, classicConnection(0x00, 0x40, kAddrB)),         // 8 reused for another device
                    h4(2, aclFor(0x40)),                                  // 9 -> BD_ADDR B
                    h4(4, classicConnection(0x0c, 0x42, kAddrA)),         // 10 failed connection: no mapping
                    h4(2, aclFor(0x42)),                                  // 11
                    h4(4, leEnhancedConnection(0x43, kAddrA)),            // 12
                    h4(2, aclFor(0x43))});                                // 13 -> BD_ADDR A
    const auto &p = c.packets;
    EXPECT_EQ(p[0].destination, "0x0040");
    EXPECT_EQ(p[2].destination, "00:1a:7d:da:71:13");
    EXPECT_EQ(p[2].source, "host");
    EXPECT_EQ(p[2].app_code, 0x8040) << "the handle stays available to bt.handle";
    EXPECT_EQ(p[4].destination, "11:22:33:44:55:66");
    EXPECT_EQ(p[6].destination, "0x0040");
    EXPECT_EQ(p[8].destination, "11:22:33:44:55:66");
    EXPECT_EQ(p[10].destination, "0x0042");
    EXPECT_EQ(p[12].destination, "00:1a:7d:da:71:13");
    for (const auto &pk: p) EXPECT_FALSE(pk.protocol.empty());

    // the address shown in the field tree of the event lies on the wire bytes
    packet::PacketInfo details(2);
    details.link_type = 187;
    std::vector<char> raw(c.frames[1].begin(), c.frames[1].end());
    c.parser.sessions().freeze();
    c.parser.parsePacket(details, raw, dissect::ParseMode::Full);
    const auto *conn = find(details.fields, "Bluetooth Connection: handle 0x0040, BD_ADDR 00:1a:7d:da:71:13");
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(std::vector<uint8_t>(c.frames[1].begin() + conn->offset, c.frames[1].begin() + conn->offset + conn->length), kAddrA);
}

TEST(Bluetooth, ReplayReadsTheConnectionMappingTheLoadPassWrote) {
    Capture c(187, {h4(4, classicConnection(0x00, 0x40, kAddrA)), h4(2, aclFor(0x40)), h4(4, disconnection(0x40)),
                    h4(4, classicConnection(0x00, 0x40, kAddrB)), h4(2, aclFor(0x40)), h4(2, aclFor(0x44))});
    c.parser.sessions().freeze();
    for (size_t i = 0; i < c.frames.size(); ++i) {
        packet::PacketInfo replay(static_cast<int>(i) + 1);
        replay.link_type = 187;
        std::vector<char> raw(c.frames[i].begin(), c.frames[i].end());
        c.parser.parsePacket(replay, raw, dissect::ParseMode::Replay);
        EXPECT_EQ(replay.source, c.packets[i].source) << i;
        EXPECT_EQ(replay.destination, c.packets[i].destination) << i;
        EXPECT_EQ(replay.app_code, c.packets[i].app_code) << i;
        EXPECT_EQ(replay.info, c.packets[i].info) << i;
    }
    EXPECT_EQ(c.packets[1].destination, "00:1a:7d:da:71:13") << "an earlier connection of a reused handle keeps its address";
    EXPECT_EQ(c.packets[4].destination, "11:22:33:44:55:66");
    EXPECT_EQ(c.packets[5].destination, "0x0044");
    // frozen tables take no new connections: replaying an event does not change what the tables say
    EXPECT_EQ(*c.parser.sessions().bluetoothAddressOf(dissect::SessionTables::bluetoothLinkKey(0xFFFF, 0x40), 2), (std::array<uint8_t, 6>{0x13, 0x71, 0xDA, 0x7D, 0x1A, 0x00}));
    EXPECT_EQ(c.parser.sessions().bluetoothAddressOf(dissect::SessionTables::bluetoothLinkKey(0xFFFF, 0x40), 3), nullptr);
}

TEST(Bluetooth, ConnectionsAreKeptPerAdapter) {
    // Linux monitor: adapter 0 and adapter 1 both use handle 0x0040 for different devices
    Capture c(254, {monitor(0, 3, cat({0x03, 0x0b, 0x00, 0x40, 0x00}, cat(kAddrA, {0x01, 0x00}))),
                    monitor(1, 3, cat({0x03, 0x0b, 0x00, 0x40, 0x00}, cat(kAddrB, {0x01, 0x00}))),
                    monitor(0, 5, kAclAtt), monitor(1, 5, kAclAtt), monitor(2, 5, kAclAtt)});
    EXPECT_EQ(c.packets[2].source, "00:1a:7d:da:71:13");
    EXPECT_EQ(c.packets[3].source, "11:22:33:44:55:66");
    EXPECT_EQ(c.packets[4].source, "0x0040");
}

TEST(Bluetooth, ConnectionEventsThatAreCutShortOrMalformedMapNothing) {
    Bytes shortClassic = classicConnection(0x00, 0x40, kAddrA);
    shortClassic.resize(shortClassic.size() - 4);   // BD_ADDR cut: the event parameter length still says 11
    Bytes shortLe = leConnection(0x41, kAddrB);
    shortLe.resize(10);
    Capture c(187, {h4(4, shortClassic), h4(4, shortLe), h4(2, aclFor(0x40)), h4(2, aclFor(0x41))});
    EXPECT_EQ(c.packets[2].destination, "0x0040");
    EXPECT_EQ(c.packets[3].destination, "0x0041");
}

TEST(Bluetooth, TableOverflowKeepsHandlesInsteadOfAddresses) {
    dissect::SessionTables tables(sizeof(dissect::BluetoothLink) + 32);   // room for exactly one connection
    EXPECT_TRUE(tables.openBluetoothLink(dissect::SessionTables::bluetoothLinkKey(0, 1), kAddrA.data(), 1));
    EXPECT_FALSE(tables.openBluetoothLink(dissect::SessionTables::bluetoothLinkKey(0, 2), kAddrB.data(), 2));
    EXPECT_TRUE(tables.isTableStateLost("bluetooth"));
    EXPECT_EQ(tables.bluetoothAddressOf(dissect::SessionTables::bluetoothLinkKey(0, 2), 3), nullptr);
    tables.freeze();
    EXPECT_FALSE(tables.closeBluetoothLink(dissect::SessionTables::bluetoothLinkKey(0, 1), 4));
}

TEST(Bluetooth, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(h4(4, classicConnection(0x00, 0x40, kAddrA)), 21, 400, 187);
    framesweep::sweep(h4(4, leConnection(0x41, kAddrB)), 22, 400, 187);
    framesweep::sweep(h4(4, leEnhancedConnection(0x43, kAddrA)), 23, 400, 187);
    framesweep::sweep(h4(4, disconnection(0x40)), 24, 400, 187);
    framesweep::sweep(monitor(0, 3, classicConnection(0x00, 0x40, kAddrA)), 25, 400, 254);
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

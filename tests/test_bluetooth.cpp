#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/bluetooth.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

packet::PacketInfo parseLinkPacket(uint32_t linkType, const std::vector<uint8_t> &data) {
    packet::PacketParser parser;
    packet::PacketInfo pack(1);
    pack.link_type = linkType;
    std::vector<char> raw(data.begin(), data.end());
    parser.parsePacket(pack, raw, dissect::ParseMode::Full);
    return pack;
}

} // namespace

TEST(Bluetooth, HciH4CommandPacket) {
    // Indicator 1 (Command)
    // Opcode 0x0C03 (Reset: OGF 3 = 0x03, OCF 3 = 0x0003)
    // Param len: 0
    std::vector<uint8_t> pdu = {
        0x01, // Command
        0x03, 0x0c, // Opcode 0x0c03
        0x00  // Param len 0
    };

    auto pkt = parseLinkPacket(187, pdu);

    EXPECT_EQ(pkt.protocol, "HCI");
    EXPECT_EQ(pkt.app_type, 1);
    EXPECT_NE(pkt.info.find("HCI Command"), std::string::npos) << "Actual info: " << pkt.info;
    EXPECT_NE(pkt.info.find("OGF"), std::string::npos) << "Actual info: " << pkt.info;
}

TEST(Bluetooth, HciH4EventPacket) {
    // Indicator 4 (Event)
    // Event code: 0x0E (Command Complete)
    // Param len: 4
    // Num HCI Cmd packets: 1, Opcode: 0x0C03, Status: 0
    std::vector<uint8_t> pdu = {
        0x04, // Event
        0x0e, // Command Complete
        0x04, // Param len
        0x01, 0x03, 0x0c, 0x00
    };

    auto pkt = parseLinkPacket(187, pdu);

    EXPECT_EQ(pkt.protocol, "HCI");
    EXPECT_EQ(pkt.app_type, 4);
    EXPECT_NE(pkt.info.find("Command Complete"), std::string::npos);
}

TEST(Bluetooth, HciH4AclWithL2capAttExchangeMtu) {
    // Indicator 2 (ACL Data)
    // Handle 0x0040 (pb=0, bc=0) -> 0x40, 0x00
    // Total ACL len: 7 -> 0x07, 0x00
    // L2CAP Length: 3 -> 0x03, 0x00
    // L2CAP CID: 4 (ATT) -> 0x04, 0x00
    // ATT Opcode: 0x02 (Exchange MTU Request)
    // Client MTU: 512 (0x0200) -> 0x00, 0x02
    std::vector<uint8_t> pdu = {
        0x02, // ACL Data
        0x40, 0x00, // Handle 0x0040
        0x07, 0x00, // ACL Length = 7
        // L2CAP:
        0x03, 0x00, // L2CAP Length = 3
        0x04, 0x00, // CID = 4 (ATT)
        // ATT:
        0x02,       // Exchange MTU Request
        0x00, 0x02  // Client MTU = 512
    };

    auto pkt = parseLinkPacket(187, pdu);

    EXPECT_EQ(pkt.protocol, "ATT");
    EXPECT_NE(pkt.info.find("Exchange MTU Request"), std::string::npos);
    EXPECT_NE(pkt.info.find("512"), std::string::npos);
}

TEST(Ieee802154, DataAcknowledgmentFrame) {
    // FCF: 0x0002 (Type: Acknowledgment = 2, all flags 0)
    // Seq: 42
    std::vector<uint8_t> pdu = {
        0x02, 0x00, // FCF = Ack
        42          // Seq 42
    };

    auto pkt = parseLinkPacket(195, pdu);

    EXPECT_EQ(pkt.protocol, "802.15.4");
    EXPECT_EQ(pkt.app_type, 2); // Ack
    EXPECT_NE(pkt.info.find("Acknowledgment"), std::string::npos);
    EXPECT_NE(pkt.info.find("Seq 42"), std::string::npos);
}

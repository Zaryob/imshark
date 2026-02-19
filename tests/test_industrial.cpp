#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/industrial.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

std::vector<char> makeTcpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &tcpPayload) {
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };

    size_t ipTotalLen = 20 + 20 + tcpPayload.size();
    std::vector<uint8_t> ip = {
        0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x00, 0x01, 0x00, 0x00,
        64, 6, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };

    uint32_t csum = 0;
    for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ip[10] = static_cast<uint8_t>(folded >> 8);
    ip[11] = static_cast<uint8_t>(folded & 0xff);

    std::vector<uint8_t> tcp = {
        static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
        static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
        0, 0, 0, 1, // Seq 1
        0, 0, 0, 1, // Ack 1
        0x50, 0x18, 0x20, 0x00, // ACK + PSH
        0, 0, 0, 0 // checksum placeholder
    };

    frame.insert(frame.end(), ip.begin(), ip.end());
    frame.insert(frame.end(), tcp.begin(), tcp.end());
    frame.insert(frame.end(), tcpPayload.begin(), tcpPayload.end());

    std::vector<char> out(frame.size());
    std::memcpy(out.data(), frame.data(), frame.size());
    return out;
}

packet::PacketInfo parseLinkPacket(uint32_t linkType, const std::vector<uint8_t> &data) {
    packet::PacketParser parser;
    packet::PacketInfo pack(1);
    pack.link_type = linkType;
    std::vector<char> raw(data.begin(), data.end());
    parser.parsePacket(pack, raw, dissect::ParseMode::Full);
    return pack;
}

} // namespace

TEST(Industrial, ModbusReadHoldingRegistersRequest) {
    // MBAP Header (7 bytes):
    // TransID: 0x0001
    // ProtoID: 0x0000 (Modbus)
    // Length: 6 (Unit ID + PDU)
    // UnitID: 1
    // PDU: Function 0x03 (Read Holding Registers), Starting Address 0x0000, Quantity 0x000A
    std::vector<uint8_t> pdu = {
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x06,
        0x01,
        0x03,
        0x00, 0x00,
        0x00, 0x0a
    };

    auto pkt = parse(makeTcpPacket(54321, 502, pdu));

    EXPECT_EQ(pkt.protocol, "Modbus");
    EXPECT_EQ(pkt.app_type, 3);
    EXPECT_NE(pkt.info.find("Read Holding Registers"), std::string::npos);
    EXPECT_NE(pkt.info.find("TransID 1"), std::string::npos);
}

TEST(Industrial, Dnp3ReadRequest) {
    // DNP3 Frame (10 bytes header + application)
    // Start: 0x05, 0x64
    // Length: 7
    // Control: 0xC4 (DIR=1, PRM=1, FCB=0, FCV=0, Function=Reset Link)
    // Dest: 1
    // Source: 2
    // Link CRC: 0x1234
    // Transport header: 0xC0 (FIN=1, FIR=1, SEQ=0)
    // App Control: 0xC0
    // App FC: 1 (Read)
    std::vector<uint8_t> pdu = {
        0x05, 0x64,
        0x07,
        0xc4,
        0x01, 0x00, // Dest 1
        0x02, 0x00, // Source 2
        0x34, 0x12, // CRC
        0xc0,       // Transport
        0xc0,       // App Control
        0x01        // App FC 1 (Read)
    };

    auto pkt = parse(makeTcpPacket(54321, 20000, pdu));

    EXPECT_EQ(pkt.protocol, "DNP3");
    EXPECT_EQ(pkt.source, "2");
    EXPECT_EQ(pkt.destination, "1");
    EXPECT_NE(pkt.info.find("Read"), std::string::npos);
}

TEST(Industrial, SocketCanStandardFrame) {
    // Standard 11-bit CAN frame (ID 0x123, DLC 4, Data: 0xAA 0xBB 0xCC 0xDD)
    std::vector<uint8_t> pdu = {
        0x00, 0x00, 0x01, 0x23, // CAN ID: 0x123 (big endian)
        0x04,                   // DLC = 4
        0x00, 0x00, 0x00,       // padding
        0xaa, 0xbb, 0xcc, 0xdd, // Data
        0x00, 0x00, 0x00, 0x00  // padding up to 16 bytes
    };

    auto pkt = parseLinkPacket(227, pdu);

    EXPECT_EQ(pkt.protocol, "CAN");
    EXPECT_EQ(pkt.app_type, 0x123);
    EXPECT_NE(pkt.info.find("CAN ID: 0x123"), std::string::npos);
    EXPECT_NE(pkt.info.find("DLC: 4"), std::string::npos);
}

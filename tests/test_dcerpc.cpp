#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/dcerpc.h>
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

} // namespace

TEST(DceRpc, BindPacketEndpointMapper) {
    // DCE/RPC Bind packet:
    // Version 5.0, PDU Type 11 (Bind), Flags 0x03 (PFC_FIRST_FRAG | PFC_LAST_FRAG)
    // Data representation: 0x10, 0x00, 0x00, 0x00 (little endian ASCII IEEE)
    // Frag length: 72 (0x48), Auth length: 0, Call ID: 1
    // Max xmit: 5840, Max recv: 5840, Assoc group: 0
    // Ctx items: 1, Reserved: 0, Ctx ID: 0, Num transfer: 1, Reserved: 0
    // Abstract syntax: e1af830d-5d1f-11c9-91a4-08002b14a0fa (Endpoint Mapper)
    std::vector<uint8_t> pdu = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, // Frag length = 72
        0x00, 0x00, // Auth length = 0
        0x01, 0x00, 0x00, 0x00, // Call ID = 1
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        // Abstract Syntax UUID: e1af830d-5d1f-11c9-91a4-08002b14a0fa
        0x0d, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
        0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
        0x03, 0x00, 0x00, 0x00, // Version 3.0
        // Transfer Syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860 (NDR)
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00  // Version 2.0
    };

    auto pkt = parse(makeTcpPacket(54321, 135, pdu));

    EXPECT_EQ(pkt.protocol, "DCERPC");
    EXPECT_EQ(pkt.app_type, 11); // Bind
    EXPECT_NE(pkt.info.find("Bind"), std::string::npos);
    EXPECT_NE(pkt.info.find("Endpoint Mapper"), std::string::npos);
}

TEST(DceRpc, RequestPacketWithOpnum) {
    // DCE/RPC Request packet:
    // Version 5.0, PDU Type 0 (Request), Flags 0x03
    // Data representation: 0x10, 0x00, 0x00, 0x00 (little endian)
    // Frag length: 24, Auth length: 0, Call ID: 1
    // Alloc hint: 0, Context ID: 0, Opnum: 3
    std::vector<uint8_t> pdu = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x18, 0x00, // Frag length = 24
        0x00, 0x00, // Auth length = 0
        0x01, 0x00, 0x00, 0x00, // Call ID = 1
        0x00, 0x00, 0x00, 0x00, // Alloc hint = 0
        0x00, 0x00,             // Context ID = 0
        0x03, 0x00              // Opnum = 3
    };

    auto pkt = parse(makeTcpPacket(54321, 135, pdu));

    EXPECT_EQ(pkt.protocol, "DCERPC");
    EXPECT_EQ(pkt.app_type, 0); // Request
    EXPECT_NE(pkt.info.find("Request"), std::string::npos);
    EXPECT_NE(pkt.info.find("Opnum: 3"), std::string::npos);
}

TEST(DceRpc, StreamFramer) {
    // Valid 24-byte packet header
    std::vector<uint8_t> streamData = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00
    };

    auto f1 = frameDceRpc(reinterpret_cast<const char *>(streamData.data()), 8);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameDceRpc(reinterpret_cast<const char *>(streamData.data()), 20);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameDceRpc(reinterpret_cast<const char *>(streamData.data()), 24);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 24u);
}

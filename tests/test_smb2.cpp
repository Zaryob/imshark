#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/smb2.h>
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

TEST(Smb2, NegotiateProtocolRequest) {
    // NetBIOS session header (4 bytes) + SMB2 header (64 bytes)
    std::vector<uint8_t> pdu = {
        0x00, 0x00, 0x00, 0x40, // NetBIOS: len = 64
        0xfe, 'S', 'M', 'B',     // ProtocolId
        64, 0,                  // StructureSize = 64
        0, 0,                   // CreditCharge = 0
        0, 0, 0, 0,             // Status = 0
        0x00, 0x00,             // Command = 0 (Negotiate)
        1, 0,                   // CreditsRequested = 1
        0x00, 0x00, 0x00, 0x00, // Flags = 0 (Request)
        0, 0, 0, 0,             // NextCommand = 0
        1, 0, 0, 0, 0, 0, 0, 0, // MessageId = 1
        0, 0, 0, 0,             // Reserved
        0, 0, 0, 0,             // TreeId = 0
        0, 0, 0, 0, 0, 0, 0, 0, // SessionId = 0
        // Signature (16 bytes)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    auto pkt = parse(makeTcpPacket(54321, 445, pdu));

    EXPECT_EQ(pkt.protocol, "SMB2");
    EXPECT_EQ(pkt.app_type, 0); // Negotiate
    EXPECT_NE(pkt.info.find("Negotiate Request"), std::string::npos);
}

TEST(Smb2, SessionSetupResponseSuccess) {
    // SMB2 Session Setup Response (Command = 1, Flags = 1 (Response), Status = 0)
    std::vector<uint8_t> pdu = {
        0x00, 0x00, 0x00, 0x40, // NetBIOS: len = 64
        0xfe, 'S', 'M', 'B',     // ProtocolId
        64, 0,                  // StructureSize = 64
        0, 0,                   // CreditCharge = 0
        0x00, 0x00, 0x00, 0x00, // Status = STATUS_SUCCESS
        0x01, 0x00,             // Command = 1 (Session Setup)
        1, 0,                   // CreditsGranted = 1
        0x01, 0x00, 0x00, 0x00, // Flags = 1 (Response)
        0, 0, 0, 0,             // NextCommand = 0
        2, 0, 0, 0, 0, 0, 0, 0, // MessageId = 2
        0, 0, 0, 0,             // Reserved
        0, 0, 0, 0,             // TreeId = 0
        0x45, 0x23, 0x01, 0, 0, 0, 0, 0, // SessionId
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    auto pkt = parse(makeTcpPacket(445, 54321, pdu));

    EXPECT_EQ(pkt.protocol, "SMB2");
    EXPECT_EQ(pkt.app_type, 1); // Session Setup
    EXPECT_NE(pkt.info.find("Session Setup Response"), std::string::npos);
    EXPECT_NE(pkt.info.find("STATUS_SUCCESS"), std::string::npos);
}

TEST(Smb2, StreamFramer) {
    std::vector<uint8_t> streamData = {0x00, 0x00, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    auto f1 = frameSmb2(reinterpret_cast<const char *>(streamData.data()), 3);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameSmb2(reinterpret_cast<const char *>(streamData.data()), 15);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameSmb2(reinterpret_cast<const char *>(streamData.data()), 20);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 20u);
}

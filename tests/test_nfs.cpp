#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/nfs.h>
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

TEST(Nfs, Nfs3GetattrCall) {
    // Record Marking: 0x80000028 (Last frag, 40 bytes)
    // RPC Call:
    // XID: 0x12345678
    // MsgType: 0 (CALL)
    // RPC Vers: 2
    // Program: 100003 (NFS, 0x000186a3)
    // Vers: 3
    // Proc: 1 (GETATTR)
    // Credential Flavor: 0 (AUTH_NONE), Length: 0
    // Verifier Flavor: 0 (AUTH_NONE), Length: 0
    std::vector<uint8_t> pdu = {
        0x80, 0x00, 0x00, 0x28, // Record Marking (40 bytes)
        0x12, 0x34, 0x56, 0x78, // XID
        0x00, 0x00, 0x00, 0x00, // CALL
        0x00, 0x00, 0x00, 0x02, // RPC version 2
        0x00, 0x01, 0x86, 0xa3, // Program 100003 (NFS)
        0x00, 0x00, 0x00, 0x03, // Version 3
        0x00, 0x00, 0x00, 0x01, // Proc 1 (GETATTR)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Auth Null
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Verifier Null
    };

    auto pkt = parse(makeTcpPacket(54321, 2049, pdu));

    EXPECT_EQ(pkt.protocol, "NFS");
    EXPECT_EQ(pkt.app_type, 1); // GETATTR
    EXPECT_NE(pkt.info.find("NFS v3 GETATTR Call"), std::string::npos);
    EXPECT_NE(pkt.info.find("0x12345678"), std::string::npos);
}

TEST(Nfs, PortmapGetportCall) {
    // Portmap (100000) Getport Call (Proc 3)
    std::vector<uint8_t> pdu = {
        0x80, 0x00, 0x00, 0x28, // Record Marking (40 bytes)
        0xaa, 0xbb, 0xcc, 0xdd, // XID
        0x00, 0x00, 0x00, 0x00, // CALL
        0x00, 0x00, 0x00, 0x02, // RPC version 2
        0x00, 0x01, 0x86, 0xa0, // Program 100000 (Portmap)
        0x00, 0x00, 0x00, 0x02, // Version 2
        0x00, 0x00, 0x00, 0x03, // Proc 3 (GETPORT)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    auto pkt = parse(makeTcpPacket(54321, 111, pdu));

    EXPECT_EQ(pkt.protocol, "Portmap");
    EXPECT_EQ(pkt.app_type, 3); // GETPORT
    EXPECT_NE(pkt.info.find("Portmap v2 GETPORT Call"), std::string::npos);
}

TEST(Nfs, RpcStreamFramer) {
    // 4 bytes record marker (0x8000000A: last frag, 10 bytes) + 10 bytes payload
    std::vector<uint8_t> streamData = {
        0x80, 0x00, 0x00, 0x0a,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    };

    auto f1 = frameRpc(reinterpret_cast<const char *>(streamData.data()), 3);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameRpc(reinterpret_cast<const char *>(streamData.data()), 12);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameRpc(reinterpret_cast<const char *>(streamData.data()), 14);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 14u);
}

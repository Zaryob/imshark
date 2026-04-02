// Protocol hierarchy and expert info for the directory, file-sharing and database protocols: every one has a name in the
// hierarchy and a malformed packet of each is counted by the expert info.
#include <gtest/gtest.h>

#include <functional>

#include <core.h>
#include <stats/statistics.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const stats::HierarchyNode *findNode(const stats::HierarchyNode &n, const std::string &name) {
        if (n.name == name) return &n;
        for (const auto &c: n.children) if (const auto *f = findNode(c, name)) return f;
        return nullptr;
    }

    std::vector<packet::PacketInfo> load(const std::vector<std::vector<char>> &frames, const std::string &name, std::string &path, core::FileProcessor &fp) {
        path = support::writeTemp(name + ".pcap", support::pcapBytes(frames));
        std::vector<packet::PacketInfo> packets;
        std::string message;
        EXPECT_TRUE(fp.processPcapFile(path, packets, message)) << message;
        return packets;
    }
}

TEST(EnterpriseStats, EveryProtocolHasANameInTheHierarchy) {
    struct Case { uint16_t port; bool client; std::string payload; std::string node; };
    const std::string ldap = bytes("300c02010161070a010004000400");
    const std::string krb = bytes("0000000a" "6f08") + bytes("3006a003020105");
    const std::string smb = bytes("00000040fe534d42400000000000000000000100010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000");
    const std::string dce = bytes("05000b03100000001000000001000000");
    const std::string nfs = bytes("8000001c" "12345678" "00000001" "00000000" "00000000" "00000000" "00000000" "00000000");
    const std::string pg = bytes("510000000d53454c454354203100");
    const std::string my = bytes("0100000001" "0e");
    const std::string tds = bytes("0601000800000100");
    const Case cases[] = {
        {389, false, ldap, "Lightweight Directory Access Protocol"}, {88, true, krb, "Kerberos"}, {445, true, smb, "Server Message Block 2/3"},
        {135, true, dce, "Distributed Computing Environment / Remote Procedure Calls"}, {2049, false, nfs, "Remote Procedure Call"},
        {5432, true, pg, "PostgreSQL"}, {3306, true, my, "MySQL"}, {1433, true, tds, "Tabular Data Stream"}};
    for (const auto &c: cases) {
        Flow flow(50000, c.port, "hier" + std::to_string(c.port));
        if (c.client) flow.client(c.payload); else flow.server(c.payload);
        flow.load();
        const auto root = stats::protocolHierarchy(flow.packets(), nullptr);
        EXPECT_NE(findNode(root, c.node), nullptr) << c.port << " " << flow.packets()[0].protocol;
    }
    // the NFS calls have their own names
    Flow call(50000, 2049, "hier_nfs_call");
    call.client(bytes("80000030" "12345678" "00000000" "00000002" "000186a3" "00000003" "00000000" "00000000" "00000000" "00000000" "00000000" "00000000"));
    call.load();
    EXPECT_NE(findNode(stats::protocolHierarchy(call.packets(), nullptr), "Network File System"), nullptr);
}

namespace {
    // one TCP segment (or UDP datagram) carrying `payload` between 10.0.0.1:50000 and 10.0.0.2:port, from the client or the server side
    std::vector<char> segment(uint16_t port, bool fromServer, bool udp, const std::string &payload) {
        char p[8];
        std::snprintf(p, sizeof p, "%04x", port);
        if (udp) return fromServer ? support::udpPacket("0a000002", "0a000001", p, "c350", payload) : support::udpPacket("0a000001", "0a000002", "c350", p, payload);
        return fromServer ? support::tcpPacket("0a000002", "0a000001", p, "c350", "00000001", "00000001", "18", payload)
                          : support::tcpPacket("0a000001", "0a000002", "c350", p, "00000001", "00000001", "18", payload);
    }

    uint64_t malformedPackets(const std::vector<char> &frame, const std::string &name) {
        std::string path;
        core::FileProcessor fp;
        const auto packets = load({frame}, name, path, fp);
        uint64_t n = 0;
        for (const auto &item: stats::expertInfo(packets, nullptr)) if (item.summary == "Malformed packet") n += item.count;
        std::remove(path.c_str());
        return n;
    }
}

TEST(EnterpriseStats, AMalformedMessageOfEachProtocolIsCountedByTheExpertInfo) {
    // each message is complete (its own length field says so, or it is a whole datagram) and its body does not decode
    struct Case { const char *name; uint16_t port; bool fromServer, udp; std::string payload; };
    const Case cases[] = {
        {"ldap", 389, false, false, bytes("31050201016000")},                                         // not an LDAPMessage SEQUENCE
        {"kerberos", 88, false, true, bytes("6a20" "3003020105")},                                    // AS-REQ that declares 32 bytes and has 5
        {"smb2", 445, false, false, bytes("0000000cfe534d424000000000000000")},                  // a complete session message of 12 bytes: no 64 byte SMB2 header
        {"nfs", 2049, false, false, bytes("80000008" "12345678" "00000000")},                        // a call record of 8 bytes: no RPC version, program, ...
        {"dcerpc", 135, false, false, bytes("05000b03" "10000000" "1c000000" "01000000" "b810b810" "00000000" "03000000")},   // Bind with 3 contexts and none present
        {"postgres", 5432, false, false, bytes("510000000100")},                                      // length below 4
        {"mysql", 3306, true, false, bytes("01000000" "ff")},                                         // ERR without an error code
        {"tds", 1433, false, false, bytes("10010010" "0000" "0100" "0000000000000000")},              // Login7 of 8 payload bytes
    };
    for (const auto &c: cases) {
        EXPECT_EQ(malformedPackets(segment(c.port, c.fromServer, c.udp, c.payload), std::string("mal_") + c.name), 1u) << c.name;
    }
}

TEST(EnterpriseStats, AMessageCutByTheSegmentIsNotMalformed) {
    // the same kinds of message, but their length fields promise more bytes than the segment holds: the rest is in the next segment
    struct Case { const char *name; uint16_t port; bool fromServer; std::string payload; };
    const Case cases[] = {
        {"ldap", 389, false, bytes("30820100" "020101")},
        {"kerberos", 88, false, bytes("00000100" "6a820080" "3081")},
        {"nfs", 2049, false, bytes("80000040" "12345678" "00000000")},
        {"dcerpc", 135, false, bytes("05000b03" "10000000" "48000000" "01000000" "b810b810" "00000000" "03000000")},
        {"postgres", 5432, false, bytes("5100000020" "53454c")},
        {"mysql", 3306, true, bytes("14000000" "ff")},
        {"tds", 1433, false, bytes("10010080" "0000" "0100" "0000000000000000")},
        {"smb2", 445, false, bytes("00000200fe534d4240000000")},
    };
    for (const auto &c: cases) {
        EXPECT_EQ(malformedPackets(segment(c.port, c.fromServer, false, c.payload), std::string("cut_") + c.name), 0u) << c.name;
    }
}

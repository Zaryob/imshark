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

TEST(EnterpriseStats, AMalformedMessageOfEachProtocolIsCountedByTheExpertInfo) {
    struct Case { uint16_t port; std::string payload; };
    const Case cases[] = {
        {389, bytes("31050201016000")},                                                    // not an LDAPMessage SEQUENCE
        {88, bytes("6a20" "3003020105")},                                                  // AS-REQ that declares 32 bytes and has 5 (UDP)
        {445, bytes("00000020fe534d4240000000")},                                          // SMB2 header cut
        {5432, bytes("510000000100")},                                                     // length below 4
        {1433, bytes("0100000400000100")},                                                 // TDS length below the header
    };
    int udpChecked = 0;
    for (const auto &c: cases) {
        std::vector<std::vector<char>> frames;
        if (c.port == 88) {
            frames.push_back(support::udpPacket("0a000001", "0a000002", "c350", "0058", c.payload));
            ++udpChecked;
        } else {
            char port[8];
            std::snprintf(port, sizeof port, "%04x", c.port);
            frames.push_back(support::tcpPacket("0a000001", "0a000002", "c350", port, "00000001", "00000001", "18", c.payload));
        }
        std::string path;
        core::FileProcessor fp;
        const auto packets = load(frames, "expert" + std::to_string(c.port), path, fp);
        bool found = false;
        for (const auto &item: stats::expertInfo(packets, nullptr)) found = found || (item.summary == "Malformed packet" && item.count == 1);
        EXPECT_TRUE(found) << "port " << c.port << ": " << packets[0].protocol << " / " << packets[0].info;
        std::remove(path.c_str());
    }
    EXPECT_EQ(udpChecked, 1);
}

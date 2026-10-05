// Portmap / rpcbind (RFC 1833) and Mount (RFC 1813 appendix I) over whole conversations: the arguments of a call, the results of its
// reply, and the program ports the portmapper announces (a later connection or datagram to such a port is ONC RPC). Messages are
// packed with the independent Python XDR encoder (scratchpad g12d/g2.py: RFC 4506 units; the mapping is four unsigned ints, a
// pmaplist / rpcblist / exports list is "TRUE entry" repeated and a final FALSE, an rpcb is prog, vers, netid, universal address and
// owner strings, a universal address "h1.h2.h3.h4.p1.p2" with port p1 * 256 + p2: 78 * 256 + 80 = 20048). Every flow is loaded the
// way the application loads a capture and decoded again packet by packet (expectReplayEqualsLoad).
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kPmGetportMount = bytes("200000010000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a5000000030000000600000000");
    const std::string kPmGetportMountReply = bytes("20000001000000010000000000000000000000000000000000004e50");
    const std::string kPmGetportMountUdp = bytes("200000070000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a5000000030000001100000000");
    const std::string kPmGetportMountUdpReply = bytes("20000007000000010000000000000000000000000000000000004e50");
    const std::string kPmGetportHttp = bytes("200000080000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a5000000030000000600000000");
    const std::string kPmGetportHttpReply = bytes("20000008000000010000000000000000000000000000000000000050");
    const std::string kPmGetportTls = bytes("200000090000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a5000000030000000600000000");
    const std::string kPmGetportTlsReply = bytes("200000090000000100000000000000000000000000000000000001bb");
    const std::string kPmGetportNfsUdp = bytes("200000020000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a3000000030000001100000000");
    const std::string kPmGetportNfsUdpReply = bytes("20000002000000010000000000000000000000000000000000000801");
    const std::string kPmGetportNone = bytes("200000030000000000000002000186a00000000200000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186b5000000040000000600000000");
    const std::string kPmGetportNoneReply = bytes("20000003000000010000000000000000000000000000000000000000");
    const std::string kPmSet = bytes("200000040000000000000002000186a00000000200000001000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000493e10000000100000011000004d2");
    const std::string kPmSetReply = bytes("20000004000000010000000000000000000000000000000000000001");
    const std::string kPmDump = bytes("200000050000000000000002000186a00000000200000004000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000");
    const std::string kPmDumpReply = bytes("20000005000000010000000000000000000000000000000000000001000186a0"
            "00000002000000060000006f00000001000186a3000000030000000600000801"
            "00000001000186a300000003000000110000080100000001000186a500000003"
            "0000000600004e5000000001000186a5000000030000001100004e5000000000");
    const std::string kPmCallit = bytes("200000060000000000000002000186a00000000200000005000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a3000000030000000000000000");
    const std::string kPmCallitReply = bytes("2000000600000001000000000000000000000000000000000000080100000004"
            "01020304");
    const std::string kRbGetaddr = bytes("200000100000000000000002000186a00000000300000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186a5000000030000000374637000000000000000000973757065"
            "7275736572000000");
    const std::string kRbGetaddrReply = bytes("2000001000000001000000000000000000000000000000000000000e31302e30"
            "2e302e322e37382e38300000");
    const std::string kRbGetaddrNone = bytes("200000110000000000000002000186a00000000400000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000186b5000000040000000375647000000000000000000973757065"
            "7275736572000000");
    const std::string kRbGetaddrNoneReply = bytes("20000011000000010000000000000000000000000000000000000000");
    const std::string kRbDump = bytes("200000120000000000000002000186a00000000400000004000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000");
    const std::string kRbDumpReply = bytes("20000012000000010000000000000000000000000000000000000001000186a0"
            "0000000400000003746370000000000e31302e302e302e322e302e3131310000"
            "0000000973757065727573657200000000000001000186a30000000400000003"
            "746370000000000c31302e302e302e322e382e31000000097375706572757365"
            "7200000000000001000186a30000000400000003756470000000000c31302e30"
            "2e302e322e382e3100000004726f6f7400000001000186a50000000300000004"
            "74637036000000093a3a312e37382e3830000000000000097375706572757365"
            "7200000000000000");
    const std::string kRbGettime = bytes("200000130000000000000002000186a00000000400000006000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000");
    const std::string kRbGettimeReply = bytes("2000001300000001000000000000000000000000000000006553f100");
    const std::string kMntCall = bytes("200000200000000000000002000186a50000000300000001000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "000000000000000c2f6578706f72742f64617461");
    const std::string kMntReply = bytes("2000002000000001000000000000000000000000000000000000000000000020"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "000000020000000100000006");
    const std::string kMntDenied = bytes("200000210000000000000002000186a50000000300000001000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000000000072f73656372657400");
    const std::string kMntDeniedReply = bytes("2000002100000001000000000000000000000000000000000000000d");
    const std::string kMnt1Call = bytes("200000220000000000000002000186a50000000100000001000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "000000000000000b2f6578706f72742f6f6c6400");
    const std::string kMnt1Reply = bytes("20000022000000010000000000000000000000000000000000000000a0a1a2a3"
            "a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const std::string kMountDump = bytes("200000230000000000000002000186a50000000300000002000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000");
    const std::string kMountDumpReply = bytes("2000002300000001000000000000000000000000000000000000000100000008"
            "636c69656e7430310000000c2f6578706f72742f646174610000000100000008"
            "636c69656e7430320000000c2f6578706f72742f686f6d6500000000");
    const std::string kMountExport = bytes("200000240000000000000002000186a50000000300000005000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "00000000");
    const std::string kMountExportReply = bytes("200000240000000100000000000000000000000000000000000000010000000c"
            "2f6578706f72742f64617461000000010000000b31302e302e302e302f323400"
            "000000010000000661646d696e73000000000000000000010000000c2f657870"
            "6f72742f686f6d650000000000000000");
    const std::string kUmnt = bytes("200000250000000000000002000186a50000000300000003000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "000000000000000c2f6578706f72742f64617461");
    const std::string kUmntReply = bytes("200000250000000100000000000000000000000000000000");
    const std::string kMntDyn = bytes("200000300000000000000002000186a50000000300000001000000010000001c"
            "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
            "000000000000000c2f6578706f72742f64617461");
    const std::string kMntDynReply = bytes("2000003000000001000000000000000000000000000000000000000000000020"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "0000000100000001");
    
    std::string mark(const std::string &m, bool last = true) {
        const uint32_t v = (last ? 0x80000000u : 0u) | static_cast<uint32_t>(m.size());
        return std::string{static_cast<char>(v >> 24), static_cast<char>(v >> 16), static_cast<char>(v >> 8), static_cast<char>(v)} + m;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr << ": " << f.error.message;
        return f.ok && f.filter.matches(p);
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }

    // one call and its reply over UDP on `port`
    Flow exchange(const std::string &name, uint16_t port, const std::string &call, const std::string &reply) {
        Flow flow(50000, port, name);
        flow.asUdp();
        flow.client(call).server(reply);
        return flow;
    }
}

TEST(Portmap, GetportAsksForAMappingAndTheReplyNamesThePort) {
    Flow flow(50000, 111, "pm_getport");
    flow.asUdp();
    flow.client(kPmGetportMount).server(kPmGetportMountReply).client(kPmGetportNone).server(kPmGetportNoneReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Portmap v2 GETPORT Call (XID: 0x20000001), prog=Mount v3 tcp");
    EXPECT_EQ(k[1].protocol, "Portmap");
    EXPECT_EQ(k[1].info, "Portmap v2 GETPORT Reply (XID: 0x20000001), port=20048");
    EXPECT_TRUE(matches("portmap.proc == 3 && portmap.port == 20048 && rpc.matched && rpc.state_accept == 0", k[1]));
    EXPECT_EQ(k[3].info, "Portmap v2 GETPORT Reply (XID: 0x20000003), port=0 (not registered)");
    EXPECT_TRUE(matches("portmap.port == 0", k[3]));
    EXPECT_FALSE(matches("portmap.port", k[0])) << "a call has no port yet";
    EXPECT_NE(find(flow.details(1).fields, "Port: 20048"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Portmap, SetAndUnsetAnswerABoolean) {
    auto flow = exchange("pm_set", 111, kPmSet, kPmSetReply);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Portmap v2 SET Call (XID: 0x20000004), prog=300001 v1 udp port=1234");
    EXPECT_EQ(flow.packets()[1].info, "Portmap v2 SET Reply (XID: 0x20000004), result=TRUE");
    flow.expectReplayEqualsLoad();
}

TEST(Portmap, DumpListsEveryMapping) {
    auto flow = exchange("pm_dump", 111, kPmDump, kPmDumpReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Portmap v2 DUMP Call (XID: 0x20000005)");
    EXPECT_EQ(k[1].info, "Portmap v2 DUMP Reply (XID: 0x20000005), 5 mappings");
    EXPECT_TRUE(matches("portmap.entries == 5", k[1]));
    const auto d = flow.details(1);
    EXPECT_NE(find(d.fields, "Mappings: 5"), nullptr);
    EXPECT_NE(find(d.fields, "NFS v3 tcp port 2049"), nullptr);
    EXPECT_NE(find(d.fields, "Mount v3 udp port 20048"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Portmap, CallitNamesTheProgramToCallAndThePortThatAnswered) {
    auto flow = exchange("pm_callit", 111, kPmCallit, kPmCallitReply);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Portmap v2 CALLIT Call (XID: 0x20000006), prog=NFS v3 proc=0");
    EXPECT_EQ(flow.packets()[1].info, "Portmap v2 CALLIT Reply (XID: 0x20000006), port=2049 results=4 bytes");
    flow.expectReplayEqualsLoad();
}

TEST(Rpcbind, GetaddrNamesTheUniversalAddress) {
    Flow flow(50000, 111, "rb_getaddr");
    flow.asUdp();
    flow.client(kRbGetaddr).server(kRbGetaddrReply).client(kRbGetaddrNone).server(kRbGetaddrNoneReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Portmap v3 GETADDR Call (XID: 0x20000010), prog=Mount v3 netid=tcp");
    EXPECT_EQ(k[1].info, "Portmap v3 GETADDR Reply (XID: 0x20000010), addr=10.0.0.2.78.80 (10.0.0.2 port 20048)");
    EXPECT_TRUE(matches("portmap.port == 20048", k[1]));
    EXPECT_EQ(k[2].info, "Portmap v4 GETADDR Call (XID: 0x20000011), prog=NLM (Network Lock Manager) v4 netid=udp");
    EXPECT_EQ(k[3].info, "Portmap v4 GETADDR Reply (XID: 0x20000011), addr=(not registered)");
    EXPECT_FALSE(matches("portmap.port", k[3]));
    flow.expectReplayEqualsLoad();
}

TEST(Rpcbind, DumpListsTheRegisteredAddressesAndGettimeTheClock) {
    Flow flow(50000, 111, "rb_dump");
    flow.asUdp();
    flow.client(kRbDump).server(kRbDumpReply).client(kRbGettime).server(kRbGettimeReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "Portmap v4 DUMP Reply (XID: 0x20000012), 4 mappings");
    EXPECT_EQ(k[3].info, "Portmap v4 GETTIME Reply (XID: 0x20000013), time=1700000000");
    const auto d = flow.details(1);
    EXPECT_NE(find(d.fields, "NFS v4 tcp 10.0.0.2.8.1 owner superuser"), nullptr);
    EXPECT_NE(find(d.fields, "Mount v3 tcp6 ::1.78.80 owner superuser"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Mount, MntReturnsTheFileHandleAndTheFlavors) {
    Flow flow(50000, 111, "mount_mnt");
    flow.asUdp();
    flow.on(50000, 2049);   // the mount program is reached on port 2049 here (a Decode As would do the same elsewhere)
    flow.client(kMntCall).server(kMntReply).client(kMntDenied).server(kMntDeniedReply).client(kMnt1Call).server(kMnt1Reply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].protocol, "Mount");
    EXPECT_EQ(k[1].info, "Mount v3 MNT Reply (XID: 0x20000020), MNT3_OK fh=a0a1a2a3a4a5a6a7... flavors=AUTH_SYS,RPCSEC_GSS");
    EXPECT_TRUE(matches("mount.status == 0 && rpc.matched && rpc.programversion == 3", k[1]));
    EXPECT_EQ(k[3].info, "Mount v3 MNT Reply (XID: 0x20000021), MNT3ERR_ACCES");
    EXPECT_TRUE(matches("mount.status == 13", k[3]));
    EXPECT_EQ(k[5].info, "Mount v1 MNT Reply (XID: 0x20000022), MNT3_OK fh=a0a1a2a3a4a5a6a7...");
    EXPECT_NE(find(flow.details(1).fields, "File Handle: a0a1a2a3a4a5a6a7... (32 bytes)"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "Authentication Flavors: AUTH_SYS,RPCSEC_GSS"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Mount, DumpExportAndUmnt) {
    Flow flow(50000, 2049, "mount_lists");
    flow.asUdp();
    flow.client(kMountDump).server(kMountDumpReply).client(kMountExport).server(kMountExportReply).client(kUmnt).server(kUmntReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "Mount v3 DUMP Reply (XID: 0x20000023), 2 mounts");
    EXPECT_EQ(k[3].info, "Mount v3 EXPORT Reply (XID: 0x20000024), 2 exports");
    EXPECT_EQ(k[4].info, "Mount v3 UMNT Call (XID: 0x20000025), path=/export/data");
    EXPECT_EQ(k[5].info, "Mount v3 UMNT Reply (XID: 0x20000025) Accepted SUCCESS") << "void result";
    EXPECT_NE(find(flow.details(1).fields, "client02:/export/home"), nullptr);
    EXPECT_NE(find(flow.details(3).fields, "/export/data (10.0.0.0/24,admins)"), nullptr);
    EXPECT_NE(find(flow.details(3).fields, "/export/home"), nullptr);
    flow.expectReplayEqualsLoad();
}

// ---- program ports the portmapper announced --------------------------------------------------------------------------------------

TEST(RpcPorts, AConnectionToAnAnnouncedTcpPortIsRpcFromThatAnswerOn) {
    Flow flow(50002, 20048, "ports_tcp");
    flow.client(mark(kMntDyn));                                   // before the answer: nothing says this is RPC
    flow.on(50000, 111).client(mark(kPmGetportMount)).server(mark(kPmGetportMountReply));
    flow.on(50001, 20048).client(mark(kMntDyn)).server(mark(kMntDynReply));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "TCP");
    EXPECT_EQ(k[3].protocol, "Mount");
    EXPECT_EQ(k[3].info, "Mount v3 MNT Call (XID: 0x20000030), path=/export/data");
    EXPECT_EQ(k[4].info, "Mount v3 MNT Reply (XID: 0x20000030), MNT3_OK fh=a0a1a2a3a4a5a6a7... flavors=AUTH_SYS");
    EXPECT_TRUE(matches("mount.path == \"/export/data\" && rpc.program == 100005", k[3]));
    flow.expectReplayEqualsLoad();
    EXPECT_EQ(flow.details(0).protocol, "TCP") << "Replay of the earlier packet is as it was";
}

TEST(RpcPorts, ADatagramToAnAnnouncedUdpPortIsRpcToo) {
    Flow flow(50002, 20048, "ports_udp");
    flow.asUdp();
    flow.client(kMntDyn);
    flow.on(50000, 111).client(kPmGetportMountUdp).server(kPmGetportMountUdpReply);
    flow.on(50001, 20048).client(kMntDyn).server(kMntDynReply);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "UDP");
    EXPECT_EQ(k[3].protocol, "Mount");
    EXPECT_EQ(k[4].protocol, "Mount");
    EXPECT_EQ(k[4].info.rfind("Mount v3 MNT Reply", 0), 0u);
    flow.expectReplayEqualsLoad();
}

TEST(RpcPorts, AnAnswerOfAnotherTransportDoesNotMapTheOtherOne) {
    Flow flow(50000, 111, "ports_transport");
    flow.client(mark(kPmGetportMount)).server(mark(kPmGetportMountReply));   // tcp
    flow.on(50001, 20048).asUdp();
    flow.client(kMntDyn);
    flow.load();
    EXPECT_EQ(flow.packets()[2].protocol, "UDP");
}

TEST(RpcPorts, AnAnswerWithoutItsCallMapsNothing) {
    Flow flow(50000, 111, "ports_unmatched");
    flow.server(mark(kPmGetportMountReply));
    flow.on(50001, 20048).client(mark(kMntDyn));
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "RPC");
    EXPECT_EQ(flow.packets()[1].protocol, "TCP");
}

TEST(RpcPorts, DumpAndRpcbindAnnounceThePortsToo) {
    Flow dump(50000, 111, "ports_dump");
    dump.client(mark(kPmDump)).server(mark(kPmDumpReply));
    dump.on(50001, 20048).client(mark(kMntDyn));
    dump.load();
    EXPECT_EQ(dump.packets()[2].protocol, "Mount");
    dump.expectReplayEqualsLoad();

    Flow rb(50000, 111, "ports_getaddr");
    rb.client(mark(kRbGetaddr)).server(mark(kRbGetaddrReply));
    rb.on(50001, 20048).client(mark(kMntDyn));
    rb.load();
    EXPECT_EQ(rb.packets()[2].protocol, "Mount");
    rb.expectReplayEqualsLoad();
}

TEST(RpcPorts, APortAProtocolOwnsIsNeverTakenOver) {
    // the answer claims port 80 and 443; the registry's own HTTP port stays HTTP and a TLS hello stays TLS
    Flow flow(50000, 111, "ports_guard");
    flow.client(mark(kPmGetportHttp)).server(mark(kPmGetportHttpReply)).client(mark(kPmGetportTls)).server(mark(kPmGetportTlsReply));
    flow.on(50001, 80).client("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
    flow.on(50002, 443).client(bytes("160301" "0004" "01000000"));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[4].protocol, "HTTP");
    EXPECT_EQ(k[5].protocol, "TLS");
    flow.expectReplayEqualsLoad();
}

TEST(RpcPorts, BytesThatAreNotRpcOnAnAnnouncedPortStayTcp) {
    Flow flow(50000, 111, "ports_junk");
    flow.client(mark(kPmGetportMount)).server(mark(kPmGetportMountReply));
    flow.on(50001, 20048).client("hello, this is not a record\r\n").client(bytes("1234567800000009" "00000002"));
    flow.load();
    EXPECT_EQ(flow.packets()[2].protocol, "TCP");
    EXPECT_EQ(flow.packets()[3].protocol, "TCP");
    flow.expectReplayEqualsLoad();
}

TEST(RpcPrograms, TruncationAndMutationStayInsideTheFrame) {
    const std::string *messages[] = {&kPmGetportMount, &kPmGetportMountReply, &kPmDumpReply, &kPmCallit, &kPmCallitReply, &kRbGetaddr, &kRbGetaddrReply,
                                     &kRbDumpReply, &kMntCall, &kMntReply, &kMnt1Reply, &kMountDumpReply, &kMountExportReply, &kUmnt};
    uint32_t seed = 0x5300;
    for (const std::string *m: messages) {
        appflow::sweepPayload(mark(*m), 111, seed++);
        appflow::sweepDatagram(*m, 111, seed++);
    }
}

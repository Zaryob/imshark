// ONC RPC (RFC 5531), NFS v3 (RFC 1813) / v4 (RFC 7530), Portmap (RFC 1833), Mount: messages packed with Python's struct module as XDR
// (RFC 4506: 4 byte big-endian units, strings and opaques length-prefixed and padded to 4) - call "xid, 0, 2, prog, vers, proc,
// credential (flavor, opaque<400>), verifier, arguments", reply "xid, 1, reply_stat, ..." - with the TCP record mark in front
// ("last fragment bit | length"). Python's encoder is the oracle.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/nfs.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kGetattr = bytes("123456780000000000000002000186a300000003000000010000000100000020"
        "05f5e10000000008636c69656e743031000003e8000000640000000100000064"
        "0000000000000000000000200102030405060708090a0b0c0d0e0f1011121314"
        "15161718191a1b1c1d1e1f20");
    const std::string kNull = bytes("123456790000000000000002000186a300000003000000000000000000000000"
        "0000000000000000");
    const std::string kLookup = bytes("1234567a0000000000000002000186a300000003000000030000000000000000"
        "0000000000000000000000200102030405060708090a0b0c0d0e0f1011121314"
        "15161718191a1b1c1d1e1f200000000a7265706f72742e7478740000");
    const std::string kRead = bytes("1234567b0000000000000002000186a300000003000000060000000000000000"
        "0000000000000000000000200102030405060708090a0b0c0d0e0f1011121314"
        "15161718191a1b1c1d1e1f20000000000000100000002000");
    const std::string kWrite = bytes("1234567c0000000000000002000186a300000003000000070000000000000000"
        "0000000000000000000000200102030405060708090a0b0c0d0e0f1011121314"
        "15161718191a1b1c1d1e1f200000000000002000000000040000000200000004"
        "64617461");
    const std::string kCompound = bytes("1234567d0000000000000002000186a300000004000000010000000000000000"
        "0000000000000000000000000000000000000002000000180000000a");
    const std::string kCompound41 = bytes("1234567e0000000000000002000186a300000004000000010000000000000000"
        "0000000000000000000000000000000100000003000000350000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000");
    const std::string kGetport = bytes("aabbccdd0000000000000002000186a000000002000000030000000000000000"
        "0000000000000000000186a3000000030000000600000000");
    const std::string kMnt = bytes("aabbccde0000000000000002000186a500000003000000010000000000000000"
        "00000000000000000000000c2f6578706f72742f64617461");
    const std::string kOther = bytes("aabbccdf0000000000000002000186b500000004000000050000000000000000"
        "0000000000000000");
    const std::string kReplyOk = bytes("12345678000000010000000000000000000000000000000000000000");
    const std::string kReplyMismatch = bytes("1234567a00000001000000000000000000000000000000020000000200000003");
    const std::string kReplyUnavail = bytes("1234567b0000000100000000000000000000000000000003");
    const std::string kReplyDeniedRpc = bytes("1234567c0000000100000001000000000000000200000002");
    const std::string kReplyDeniedAuth = bytes("1234567d00000001000000010000000100000001");

    const std::string kClientHello = bytes("160301" "0004" "01000000");

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

    packet::PacketInfo udp(const std::string &payload, const char *port = "0801") {
        return support::parse(support::udpPacket("0a000001", "0a000002", "c350", port, payload));
    }
}

TEST(Nfs, Version3CallsNameTheirFileHandleNameOffsetAndCount) {
    Flow flow(50000, 2049, "nfs_calls");
    flow.client(mark(kGetattr)).client(mark(kNull)).client(mark(kLookup)).client(mark(kRead)).client(mark(kWrite));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "NFS");
    EXPECT_EQ(k[0].info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708...");
    EXPECT_TRUE(matches("rpc && nfs && rpc.xid == 0x12345678 && rpc.program == 100003 && rpc.programversion == 3 && nfs.proc == 1 && rpc.msgtyp == 0", k[0]));
    EXPECT_EQ(k[1].info, "NFS v3 NULL Call (XID: 0x12345679)");
    EXPECT_EQ(k[2].info, "NFS v3 LOOKUP Call (XID: 0x1234567a), fh=0102030405060708... name=report.txt");
    EXPECT_TRUE(matches("nfs.proc == 3 && nfs.name == \"report.txt\"", k[2]));
    EXPECT_EQ(k[3].info, "NFS v3 READ Call (XID: 0x1234567b), fh=0102030405060708... offset=4096 count=8192");
    EXPECT_EQ(k[4].info, "NFS v3 WRITE Call (XID: 0x1234567c), fh=0102030405060708... offset=8192 count=4");
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Program: NFS (100003)"), nullptr);
    EXPECT_NE(find(d.fields, "Procedure: GETATTR (1)"), nullptr);
    EXPECT_NE(find(d.fields, "Credential: AUTH_SYS machine=client01 uid=1000 gid=100"), nullptr);
    EXPECT_NE(find(d.fields, "File Handle: 0102030405060708... (32 bytes)"), nullptr);
    EXPECT_NE(find(d.fields, "Record Mark: last fragment, 108 bytes"), nullptr);
    flow.expectReplayEqualsLoad();
}

// Changed with the full COMPOUND operation list (v1.3): the Info used to say "first=PUTROOTFH"; it now lists the operations that can be followed.
TEST(Nfs, Version4CompoundListsTheOperations) {
    Flow flow(50000, 2049, "nfs_v4");
    flow.client(mark(kCompound)).client(mark(kCompound41));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "NFSv4");
    EXPECT_EQ(k[0].info, "NFS v4 COMPOUND Call (XID: 0x1234567d), minor=0 ops=2 [PUTROOTFH, GETFH]");
    EXPECT_EQ(k[1].info, "NFS v4 COMPOUND Call (XID: 0x1234567e), minor=1 ops=3 [SEQUENCE, op 0, ...]");
    EXPECT_TRUE(matches("nfs && nfs.version == 4 && nfs.proc == 1", k[0]));
}

TEST(Nfs, PortmapAndMountArguments) {
    Flow flow(50000, 111, "nfs_portmap");
    flow.client(mark(kGetport)).client(mark(kMnt)).client(mark(kOther));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "Portmap");
    EXPECT_EQ(k[0].info, "Portmap v2 GETPORT Call (XID: 0xaabbccdd), prog=NFS v3 tcp");
    EXPECT_TRUE(matches("portmap.proc == 3 && rpc.program == 100000", k[0]));
    EXPECT_EQ(k[1].protocol, "Mount");
    EXPECT_EQ(k[1].info, "Mount v3 MNT Call (XID: 0xaabbccde), path=/export/data");
    EXPECT_TRUE(matches("mount.path == \"/export/data\"", k[1]));
    EXPECT_EQ(k[2].protocol, "RPC");
    EXPECT_EQ(k[2].info, "NLM (Network Lock Manager) v4 PROC 5 Call (XID: 0xaabbccdf)");
    EXPECT_TRUE(matches("rpc.program == 100021 && !nfs", k[2]));
}

TEST(Nfs, RepliesShowTheirStatus) {
    Flow flow(50000, 2049, "nfs_replies");
    flow.server(mark(kReplyOk)).server(mark(kReplyMismatch)).server(mark(kReplyUnavail)).server(mark(kReplyDeniedRpc)).server(mark(kReplyDeniedAuth));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "RPC");
    EXPECT_EQ(k[0].info, "RPC Reply (XID: 0x12345678) Accepted SUCCESS");
    EXPECT_TRUE(matches("rpc.msgtyp == 1 && rpc.state_accept == 0 && !rpc.reply_denied", k[0]));
    EXPECT_EQ(k[1].info, "RPC Reply (XID: 0x1234567a) Accepted PROG_MISMATCH (versions 2-3)");
    EXPECT_EQ(k[2].info, "RPC Reply (XID: 0x1234567b) Accepted PROC_UNAVAIL");
    EXPECT_TRUE(matches("rpc.state_accept == 3", k[2]));
    EXPECT_EQ(k[3].info, "RPC Reply (XID: 0x1234567c) Denied RPC_MISMATCH (versions 2-2)");
    EXPECT_TRUE(matches("rpc.reply_denied", k[3]));
    EXPECT_EQ(k[4].info, "RPC Reply (XID: 0x1234567d) Denied AUTH_ERROR AUTH_BADCRED");
    EXPECT_FALSE(matches("rpc.state_accept == 1", k[4])) << "the auth status is not an accept status";
    flow.expectReplayEqualsLoad();
}

TEST(Nfs, UdpHasNoRecordMarkAndASmallXidIsNotMistakenForOne) {
    const auto call = udp(kLookup);
    EXPECT_EQ(call.protocol, "NFS");
    EXPECT_EQ(call.info, "NFS v3 LOOKUP Call (XID: 0x1234567a), fh=0102030405060708... name=report.txt");
    // an XID whose value equals the datagram length minus 4 used to be read as a record mark
    std::string small = kGetattr;
    const uint32_t xid = static_cast<uint32_t>(small.size() - 4);
    small.replace(0, 4, std::string{static_cast<char>(xid >> 24), static_cast<char>(xid >> 16), static_cast<char>(xid >> 8), static_cast<char>(xid)});
    const auto p = udp(small, "0801");
    EXPECT_EQ(p.protocol, "NFS");
    EXPECT_EQ(p.app_stream, xid);
    const auto reply = udp(kReplyOk, "0801");
    EXPECT_EQ(reply.info, "RPC Reply (XID: 0x12345678) Accepted SUCCESS");
}

// Changed with the multi-fragment reassembly (v1.3): this used to send a GETATTR record marked "not the last fragment" followed by a
// whole LOOKUP record, which RFC 5531 section 11 reads as one record (the LOOKUP bytes are the rest of it). The record is now cut into
// two fragments; test_rpc_flows.cpp has the reassembly cases.
TEST(Nfs, RecordMarkingWithSeveralFragmentsAndSegments) {
    Flow flow(50000, 2049, "nfs_marks");
    flow.client(mark(kGetattr.substr(0, 40), false)).client(mark(kGetattr.substr(40))).client(mark(kLookup))
        .client(mark(kRead).substr(0, 20)).client(mark(kRead).substr(20) + mark(kNull));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 GETATTR Call (XID: 0x12345678) [not the last fragment of the record]");
    EXPECT_EQ(k[1].info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708... [Reassembled: 2 fragments, 108 bytes]");
    EXPECT_EQ(k[2].info.rfind("NFS v3 LOOKUP Call", 0), 0u);
    EXPECT_NE(k[3].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[3].info;
    EXPECT_EQ(k[4].info.rfind("NFS v3 READ Call (XID: 0x1234567b)", 0), 0u) << k[4].info;
    EXPECT_NE(k[4].info.find(", NFS v3 NULL Call"), std::string::npos) << k[4].info;
    flow.expectReplayEqualsLoad();
}

TEST(Nfs, ATlsRecordOnTheNfsPortIsTls) {
    Flow flow(50000, 2049, "nfs_tls");
    flow.client(kClientHello);
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "TLS");
}

TEST(NfsFramer, FramesByTheRecordMark) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameRpc(s.data(), s.size()); };
    const std::string a = mark(kGetattr);
    EXPECT_EQ(frame(a.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(a.substr(0, 30)).kind, K::NeedMore);
    EXPECT_EQ(frame(a.substr(0, 30)).length, a.size());
    EXPECT_EQ(frame(a).kind, K::Complete);
    EXPECT_EQ(frame(a + a).length, a.size());
    EXPECT_EQ(frame(mark(kGetattr, false)).length, a.size()) << "the last-fragment bit is not part of the length";
    EXPECT_EQ(frame(bytes("80000000")).kind, K::Reject) << "an empty fragment carries nothing";
    EXPECT_EQ(frame(bytes("7fffffff" "00000001")).kind, K::Reject) << "bigger than the stream table buffers";
    EXPECT_EQ(frame(bytes("80000020" "00000001" "00000007")).kind, K::Reject) << "message type is neither call nor reply";
    EXPECT_EQ(frame(bytes("80000020" "00000001" "00000000" "00000009" "00000001")).kind, K::Reject) << "RPC version is not 2";
    EXPECT_EQ(frame(bytes("1603010004" "01000000")).kind, K::Reject) << "a TLS record";
}

TEST(Nfs, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kGetattr, &kLookup, &kRead, &kWrite, &kCompound, &kCompound41, &kGetport, &kMnt, &kReplyOk, &kReplyMismatch, &kReplyDeniedRpc, &kReplyDeniedAuth}) {
        appflow::sweepPayload(mark(*m), 2049, 0x4e46);
        appflow::sweepPayload(mark(*m), 111, 0x4e47);
        const auto frame = support::udpPacket("0a000001", "0a000002", "c350", "0801", *m);
        framesweep::sweep(framesweep::Bytes(frame.begin(), frame.end()), 0x4e48);
    }
}

TEST(Nfs, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"NFS", "NFSv4", "Portmap", "Mount", "RPC"});
}

// ONC RPC layer over whole conversations (nfs.cpp + onc_rpc_session.h): replies shown with the procedure of their call (xid matching),
// retransmissions, a reply that comes before its call, records of several fragments joined when the last fragment arrives. Every flow
// is loaded the way the application loads a capture and decoded again one packet at a time; the facts and the Info of the Replay must
// equal the load pass (expectReplayEqualsLoad). Messages are packed with the independent Python XDR encoder (scratchpad g12d/xdr.py:
// RFC 4506 units, RFC 5531 call / reply bodies, the record mark "last fragment bit | length"); the fragments are slices of those bytes.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kFlowGetattr = bytes("123456780000000000000002000186a30000000300000001000000010000001c"
        "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
        "00000000000000200102030405060708090a0b0c0d0e0f101112131415161718"
        "191a1b1c1d1e1f20");
    const std::string kFlowLookup = bytes("1234567a0000000000000002000186a30000000300000003000000010000001c"
        "05f5e10000000008636c69656e743031000003e8000000640000000000000000"
        "00000000000000200102030405060708090a0b0c0d0e0f101112131415161718"
        "191a1b1c1d1e1f200000000a7265706f72742e7478740000");
    const std::string kFlowReplyOk = bytes("123456780000000100000000000000000000000000000000");

    // RPCSEC_GSS credential (version 1, DATA, sequence 7, integrity, 12 byte handle) and a 22 byte checksum verifier (g12d/g5.py)
    const std::string kGssCall = bytes("500000010000000000000002000186a300000003000000010000000600000020"
        "000000010000000000000007000000010000000c111111111111111111111111"
        "00000006000000163014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000"
        "000000200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
        "1d1e1f20");
    const std::string kGssReply = bytes("50000001000000010000000000000006000000163014bbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbb000000000000");

    // integrity protected GETATTR (service 2: the arguments are a databody and a checksum, not the plain arguments), its reply, and a context
    // creation message (gss_proc INIT) (g12d/g6.py)
    const std::string kGssIntegCall = bytes("500000020000000000000002000186a300000003000000010000000600000020"
        "000000010000000000000007000000020000000c111111111111111111111111"
        "00000006000000163014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000"
        "0000002800000007000000200102030405060708090a0b0c0d0e0f1011121314"
        "15161718191a1b1c1d1e1f2000000010cccccccccccccccccccccccccccccccc");
    const std::string kGssIntegReply = bytes("50000002000000010000000000000006000000163014bbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbb00000000000000000008000000070000000000000010"
        "dddddddddddddddddddddddddddddddd");
    const std::string kGssInitCall = bytes("500000030000000000000002000186a300000003000000000000000600000020"
        "000000010000000100000000000000010000000c111111111111111111111111"
        "0000000000000000000000206082010101010101010101010101010101010101"
        "010101010101010101010101");

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

    // a record cut into fragments at the given offsets
    std::vector<std::string> fragments(const std::string &msg, std::initializer_list<size_t> cuts) {
        std::vector<std::string> out;
        size_t from = 0;
        for (const size_t c: cuts) { out.push_back(mark(msg.substr(from, c - from), false)); from = c; }
        out.push_back(mark(msg.substr(from), true));
        return out;
    }
}

TEST(RpcFlows, ARecordOfSeveralFragmentsIsDecodedWhenItsLastFragmentArrives) {
    Flow flow(50000, 2049, "rpc_frag3");
    const auto f = fragments(kFlowLookup, {70, 100});
    flow.client(f[0]).client(f[1]).client(f[2]);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 LOOKUP Call (XID: 0x1234567a) [not the last fragment of the record]") << "the header is in the first fragment, the arguments are not";
    EXPECT_EQ(k[1].protocol, "RPC");
    EXPECT_EQ(k[1].info, "RPC record fragment (30 bytes)");
    EXPECT_EQ(k[2].protocol, "NFS");
    EXPECT_EQ(k[2].info, "NFS v3 LOOKUP Call (XID: 0x1234567a), fh=0102030405060708... name=report.txt [Reassembled: 3 fragments, 120 bytes]");
    EXPECT_TRUE(matches("rpc.reassembled && nfs.name == \"report.txt\" && nfs.proc == 3", k[2]));
    EXPECT_TRUE(matches("rpc.fragment && !rpc.reassembled", k[0]));
    EXPECT_TRUE(matches("rpc.fragment && rpc && !nfs", k[1]));
    EXPECT_FALSE(matches("rpc.fragment", k[2]));
    const auto d = flow.details(2);
    EXPECT_NE(find(d.fields, "Reassembled record: 3 fragments, 120 bytes"), nullptr);
    EXPECT_NE(find(d.fields, "Fragment in frame 1"), nullptr);
    EXPECT_NE(find(d.fields, "Name: report.txt"), nullptr);
    EXPECT_NE(find(d.fields, "Procedure: LOOKUP (3)"), nullptr) << "the lines of the earlier fragments are in the tree too";
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, FragmentsThatTravelInSegmentsOfTheirOwnAreJoinedAsWell) {
    Flow flow(50000, 2049, "rpc_frag_segments");
    const auto f = fragments(kFlowLookup, {64});
    // the first fragment and the start of the second share a segment, the rest of the second comes later
    flow.client(f[0] + f[1].substr(0, 10)).client(f[1].substr(10));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 LOOKUP Call (XID: 0x1234567a) [not the last fragment of the record]");
    EXPECT_NE(k[1].info.find("name=report.txt [Reassembled: 2 fragments, 120 bytes]"), std::string::npos) << k[1].info;
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, ARecordThatEndsInsideTheCredentialIsNotMalformedInItsFirstFragment) {
    Flow flow(50000, 2049, "rpc_frag_cred");
    const auto f = fragments(kFlowGetattr, {40});
    flow.client(f[0]).client(f[1]);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "NFS");
    EXPECT_EQ(k[0].info.find("Malformed"), std::string::npos) << k[0].info;
    EXPECT_NE(k[1].info.find("fh=0102030405060708..."), std::string::npos) << k[1].info;
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, TheBytesAfterAFragmentThatPromisesMoreAreItsContinuation) {
    // the first fragment says it is not the last: whatever record follows on the stream is its rest (RFC 5531 section 11)
    Flow flow(50000, 2049, "rpc_hole");
    const auto f = fragments(kFlowLookup, {70});
    flow.client(f[0]);
    flow.client(mark(kFlowGetattr));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[1].info.find("Reassembled: 2 fragments"), std::string::npos) << k[1].info;
}

TEST(RpcFlows, AReplyIsShownWithTheProcedureOfItsCall) {
    Flow flow(50000, 2049, "rpc_match_tcp");
    flow.client(mark(kFlowGetattr)).server(mark(kFlowReplyOk));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].protocol, "NFS");
    EXPECT_EQ(k[1].info, "NFS v3 GETATTR Reply (XID: 0x12345678) Accepted SUCCESS");
    EXPECT_TRUE(matches("nfs && nfs.proc == 1 && nfs.version == 3 && rpc.msgtyp == 1 && rpc.matched && rpc.program == 100003 && rpc.programversion == 3 && rpc.state_accept == 0", k[1]));
    EXPECT_FALSE(matches("rpc.matched", k[0])) << "a call has no call to be matched with";
    const auto reply = flow.details(1);
    EXPECT_NE(find(reply.fields, "Call in frame 1"), nullptr);
    EXPECT_NE(find(reply.fields, "Remote Procedure Call (Reply NFS)"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "Reply in frame 2"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, AReplyWithoutItsCallStaysAnRpcReply) {
    Flow flow(50000, 2049, "rpc_unmatched");
    flow.server(mark(kFlowReplyOk));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "RPC");
    EXPECT_EQ(k[0].info, "RPC Reply (XID: 0x12345678) Accepted SUCCESS");
    EXPECT_TRUE(matches("rpc && !rpc.matched && !nfs", k[0]));
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, TheSameXidOnAnotherConnectionIsNotTheSameCall) {
    Flow flow(50000, 2049, "rpc_other_conn");
    flow.client(mark(kFlowGetattr));
    flow.on(50001, 2049);
    flow.server(mark(kFlowReplyOk));
    flow.load();
    EXPECT_EQ(flow.packets()[1].protocol, "RPC");
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, ARetransmittedCallAndADuplicateReplyAreFlaggedOverUdp) {
    Flow flow(50000, 2049, "rpc_retrans_udp");
    flow.asUdp();
    flow.client(kFlowGetattr).client(kFlowGetattr).server(kFlowReplyOk).server(kFlowReplyOk);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708...");
    EXPECT_EQ(k[1].info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708... [Retransmission of #1]");
    EXPECT_EQ(k[2].info, "NFS v3 GETATTR Reply (XID: 0x12345678) Accepted SUCCESS");
    EXPECT_EQ(k[3].info, "NFS v3 GETATTR Reply (XID: 0x12345678) Accepted SUCCESS [Duplicate reply]");
    EXPECT_TRUE(matches("rpc.retransmission && !rpc.duplicate_reply", k[1]));
    EXPECT_FALSE(matches("rpc.retransmission", k[0]));
    EXPECT_TRUE(matches("rpc.duplicate_reply && rpc.matched", k[3]));
    EXPECT_FALSE(matches("rpc.duplicate_reply", k[2]));
    EXPECT_NE(find(flow.details(1).fields, "Retransmission of the call in frame 1"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "Reply in frame 3"), nullptr) << "the first reply";
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, AReplyThatArrivesBeforeTheRetransmittedCallStaysUnmatched) {
    for (const bool tcp: {false, true}) {
        Flow flow(50000, 2049, tcp ? "rpc_early_tcp" : "rpc_early_udp");
        if (!tcp) flow.asUdp();
        const auto wrap = [&](const std::string &m) { return tcp ? mark(m) : m; };
        // the capture starts after the call: reply first, then the call is sent again, then its reply
        flow.server(wrap(kFlowReplyOk)).client(wrap(kFlowGetattr)).server(wrap(kFlowReplyOk));
        flow.load();
        const auto &k = flow.packets();
        EXPECT_EQ(k[0].protocol, "RPC") << tcp;
        EXPECT_EQ(k[0].info, "RPC Reply (XID: 0x12345678) Accepted SUCCESS");
        EXPECT_FALSE(matches("rpc.matched", k[0]));
        EXPECT_EQ(k[1].info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708...") << "not a retransmission of anything the table has seen";
        EXPECT_EQ(k[2].info, "NFS v3 GETATTR Reply (XID: 0x12345678) Accepted SUCCESS");
        EXPECT_TRUE(matches("rpc.matched && !rpc.duplicate_reply", k[2]));
        flow.expectReplayEqualsLoad();   // the Replay of packet 1 still shows an unmatched reply
        EXPECT_EQ(flow.details(0).protocol, "RPC");
    }
}

TEST(RpcFlows, ACallThatReusesTheXidWithAnotherProcedureIsANewCall) {
    Flow flow(50000, 2049, "rpc_xid_reuse");
    std::string lookupSameXid = kFlowLookup;
    lookupSameXid.replace(0, 4, kFlowGetattr.substr(0, 4));
    flow.client(mark(kFlowGetattr)).client(mark(lookupSameXid)).server(mark(kFlowReplyOk));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info.find("Retransmission"), std::string::npos) << k[1].info;
    EXPECT_EQ(k[2].info, "NFS v3 LOOKUP Reply (XID: 0x12345678) Accepted SUCCESS") << "the reply answers the latest call with that xid";
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, ARecordOfSeveralFragmentsCanBeAReplyToo) {
    Flow flow(50000, 2049, "rpc_frag_reply");
    const auto f = fragments(kFlowReplyOk, {16});
    flow.client(mark(kFlowGetattr)).server(f[0]).server(f[1]);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].protocol, "RPC");
    EXPECT_EQ(k[2].protocol, "NFS");
    EXPECT_EQ(k[2].info, "NFS v3 GETATTR Reply (XID: 0x12345678) Accepted SUCCESS [Reassembled: 2 fragments, 24 bytes]");
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, ARpcsecGssExchangeIsLabelledNotInterpreted) {
    Flow flow(50000, 2049, "rpc_gss");
    flow.client(mark(kGssCall)).server(mark(kGssReply));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 GETATTR Call (XID: 0x50000001), fh=0102030405060708...");
    EXPECT_EQ(k[1].info, "NFS v3 GETATTR Reply (XID: 0x50000001) Accepted SUCCESS");
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Credential: RPCSEC_GSS"), nullptr);
    EXPECT_NE(find(d.fields, "Verifier: RPCSEC_GSS"), nullptr);
    EXPECT_EQ(find(d.fields, "Credential: AUTH_SYS"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, RpcsecGssProtectionAndContextMessagesAreNotReadAsPlainArguments) {
    Flow flow(50000, 2049, "rpc_gss_protected");
    flow.client(mark(kGssIntegCall)).server(mark(kGssIntegReply)).client(mark(kGssInitCall));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "NFS v3 GETATTR Call (XID: 0x50000002) [RPCSEC_GSS protected, arguments not decoded]") << "read as plain arguments the databody length would pass for a file handle";
    EXPECT_EQ(k[1].info, "NFS v3 GETATTR Reply (XID: 0x50000002) Accepted SUCCESS [RPCSEC_GSS protected, results not decoded]");
    EXPECT_EQ(k[2].info, "NFS v3 NULL Call (XID: 0x50000003) [RPCSEC_GSS context message]");
    EXPECT_EQ(find(flow.details(0).fields, "File Handle"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(RpcFlows, NothingIsMatchedWithoutTheSessionTables) {
    // a stand-alone frame (no capture loading, no tables): the call and the reply are decoded on their own
    const auto call = support::parse(support::udpPacket("0a000001", "0a000002", "c350", "0801", kFlowGetattr));
    EXPECT_EQ(call.info, "NFS v3 GETATTR Call (XID: 0x12345678), fh=0102030405060708...");
    const auto reply = support::parse(support::udpPacket("0a000002", "0a000001", "0801", "c350", kFlowReplyOk));
    EXPECT_EQ(reply.protocol, "RPC");
}

TEST(RpcFlows, TruncationAndMutationStayInsideTheFrame) {
    const auto f = fragments(kFlowLookup, {70, 100});
    for (const auto &frag: f) appflow::sweepPayload(frag, 2049, 0x5250);
    appflow::sweepPayload(mark(kFlowReplyOk), 2049, 0x5251);
    appflow::sweepDatagram(kFlowLookup, 2049, 0x5252);
}

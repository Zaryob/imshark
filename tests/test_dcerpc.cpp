// DCE/RPC connection-oriented PDUs (C706): packed with Python's struct module and uuid.UUID(...).bytes_le / .bytes from the layouts of
// C706 chapter 12 - common header "5, 0, ptype, pfc_flags, drep[4], frag_length, auth_length, call_id"; Bind "max_xmit, max_recv,
// assoc_group, n_ctx, 3 reserved, { ctx_id, n_transfer, reserved, abstract syntax (uuid, version), transfer syntaxes }*"; Bind_ack
// with its secondary address padded to 4; Request "alloc_hint, p_cont_id, opnum, [object uuid when pfc_flags & 0x80]". The opnum
// comes BEFORE the object UUID (C706 12.6.3.1; the audit's remark that it moves to offset 24 is not what the specification says, the
// old offset 22 was right and the test below pins it down). Python's encoder is the oracle.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/dcerpc.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kBindEpm = bytes("05000b03100000004800000001000000b810b810000000000100000000000100"
        "0883afe11f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe80800"
        "2b10486002000000");
    const std::string kBindTwo = bytes("05000b03100000007400000002000000b810b810000000000200000000000100"
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800"
        "2b1048600200000001000100785734123412cdabef000123456789ac01000000"
        "045d888aeb1cc9119fe808002b10486002000000");
    const std::string kBindAck = bytes("05000c03100000004400000002000000b810b810341200000d005c504950455c"
        "73727673766300000100000000000000045d888aeb1cc9119fe808002b104860"
        "02000000");
    const std::string kBindNak = bytes("05000d031000000012000000020000000400");
    const std::string kRequest = bytes("05000003100000001c000000030000004000000000000f0001020304");
    const std::string kRequestObj = bytes("05000083100000002a0000000400000000000000010007004301000000000000"
        "c000000000000046aabb");
    const std::string kRequestBe = bytes("0500000300000000001c000000000005000000000000010200000000");
    const std::string kResponse = bytes("0500020310000000200000000300000018000000000000000000000000000000");
    const std::string kFault = bytes("05000303100000001c0000000300000000000000000000000300011c");
    const std::string kRequestFirst = bytes("0500000110000000380000000600000088130000000009000000000000000000"
        "000000000000000000000000000000000000000000000000");

    const std::string kClientHello = bytes("160301" "0004" "01000000");

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
}

TEST(DceRpc, BindListsEveryPresentationContext) {
    Flow flow(50000, 135, "dce_bind");
    flow.client(kBindEpm).client(kBindTwo).server(kBindAck).server(kBindNak);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "DCERPC");
    EXPECT_EQ(k[0].info, "Bind (CallID: 1), Bind: EPM (Endpoint Mapper)");
    EXPECT_TRUE(matches("dcerpc && dcerpc.pkt_type == 11 && dcerpc.cn_call_id == 1 && dcerpc.if_uuid == \"e1af8308-5d1f-11c9-91a4-08002b14a0fa\"", k[0]));
    EXPECT_EQ(k[1].info, "Bind (CallID: 2), Bind: SRVSVC (Server Service), SAMR (Security Account Manager)") << "only the first context was read before";
    EXPECT_EQ(k[2].info, "Bind_ack (CallID: 2), acceptance");
    EXPECT_EQ(k[3].info, "Bind_nak (CallID: 2), protocol version not supported");
    const auto d = flow.details(1);
    EXPECT_NE(find(d.fields, "Context 0: SRVSVC (Server Service) v3.0"), nullptr);
    EXPECT_NE(find(d.fields, "Context 1: SAMR (Security Account Manager) v1.0"), nullptr);
    EXPECT_NE(find(d.fields, "  Transfer Syntax: NDR transfer syntax"), nullptr);
    EXPECT_NE(find(flow.details(2).fields, "Secondary Address: \\PIPE\\srvsvc"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpc, RequestOpnumIsRightWithAndWithoutAnObjectUuid) {
    Flow flow(50000, 135, "dce_request");
    flow.client(kRequest).client(kRequestObj).client(kRequestBe).server(kResponse).server(kFault);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Request (CallID: 3), Opnum: 15");
    EXPECT_TRUE(matches("dcerpc.opnum == 15", k[0]));
    EXPECT_EQ(k[1].info, "Request (CallID: 4), Opnum: 7") << "PFC_OBJECT_UUID set: the object UUID follows the opnum";
    EXPECT_NE(find(flow.details(1).fields, "Object: 00000143-0000-0000-c000-000000000046"), nullptr);
    EXPECT_EQ(k[2].info, "Request (CallID: 5), Opnum: 258") << "big-endian data representation";
    EXPECT_TRUE(matches("dcerpc.opnum == 258", k[2]));
    EXPECT_EQ(k[3].info, "Response (CallID: 3)");
    EXPECT_FALSE(matches("dcerpc.opnum == 0", k[3])) << "a response has no opnum";
    EXPECT_EQ(k[4].info, "Fault (CallID: 3), Status: 0x1c010003");
    flow.expectReplayEqualsLoad();
}

TEST(DceRpc, FragmentFlagsAreShown) {
    Flow flow(50000, 135, "dce_frag");
    flow.client(kRequestFirst);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Request (CallID: 6), Opnum: 9 [first fragment]");
}

TEST(DceRpc, PdusSplitOverSegmentsAreReassembled) {
    Flow flow(50000, 135, "dce_split");
    flow.client(kBindTwo.substr(0, 10)).client(kBindTwo.substr(10, 50)).client(kBindTwo.substr(60));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_EQ(k[2].info.rfind("Bind (CallID: 2), Bind: SRVSVC", 0), 0u) << k[2].info;
    flow.expectReplayEqualsLoad();
}

TEST(DceRpc, ATlsRecordOnPort135IsTls) {
    Flow flow(50000, 135, "dce_tls");
    flow.client(kClientHello);
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "TLS");
}

TEST(DceRpcFramer, FramesByTheFragmentLengthInTheSenderByteOrder) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameDceRpc(s.data(), s.size()); };
    EXPECT_EQ(frame(kBindTwo.substr(0, 9)).kind, K::NeedMore);
    EXPECT_EQ(frame(kBindTwo.substr(0, 40)).kind, K::NeedMore);
    EXPECT_EQ(frame(kBindTwo.substr(0, 40)).length, kBindTwo.size());
    EXPECT_EQ(frame(kBindTwo).kind, K::Complete);
    EXPECT_EQ(frame(kRequestBe).length, kRequestBe.size());
    EXPECT_EQ(frame(kRequest + kResponse).length, kRequest.size());
    EXPECT_EQ(frame(bytes("1603010004" "01000000" "0000")).kind, K::Reject) << "a TLS record";
    EXPECT_EQ(frame(bytes("04000b03100000001000000001000000")).kind, K::Reject) << "version 4 is connectionless";
    EXPECT_EQ(frame(bytes("05000b0310000000" "0f000000")).kind, K::Reject) << "fragment shorter than the header";
    EXPECT_EQ(frame(bytes("0500ff03100000001000000001000000")).kind, K::Reject) << "unknown PDU type";
    EXPECT_EQ(frame(bytes("05000b03ff000000" "10000000")).kind, K::Reject) << "data representation";
}

TEST(DceRpc, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kBindEpm, &kBindTwo, &kBindAck, &kBindNak, &kRequest, &kRequestObj, &kRequestBe, &kResponse, &kFault, &kRequestFirst}) {
        appflow::sweepPayload(*m, 135, 0x4443);
    }
}

TEST(DceRpc, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"DCERPC"});
}

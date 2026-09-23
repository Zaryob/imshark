// DCE/RPC connection-oriented PDUs with authentication verifiers, fragmented calls and the endpoint mapper over TCP, the way the
// application loads them (Summary pass) and decodes them again (Replay): C706 chapter 12 layouts and the [MS-RPCE] 2.2.2.11 security
// trailer (auth_type, auth_level, auth_pad_length, reserved, auth_context_id, then auth_length bytes of credentials) built by the
// independent Python encoder scratchpad g12c/co.py (struct module; UUIDs through uuid.UUID(...).bytes_le; towers and the NDR answer
// of ept_map by dce.py). Calls: srvsvc on context 0 (bound), samr on context 1 (rejected), the endpoint mapper ept_map (opnum 3).
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/dcerpc.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
const std::string kBindAuth = bytes("05000b0310000000700020000a000000b810b810000000000100000000000100"
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800"
        "2b104860020000000a060000070000004e544c4d5353500001000000978208e2"
        "00000000000000000000000000000000");
const std::string kBindAckAuth = bytes("05000c03100000007c0030000a000000b810b810341200000d005c504950455c"
        "73727673766300000100000000000000045d888aeb1cc9119fe808002b104860"
        "020000000a060000070000004e544c4d53535000020000000000000038000000"
        "158289e2010203040506070800000000000000000000000000000000");
const std::string kAuth3 = bytes("05001003100000005c0040000a000000000000000a060000070000004e544c4d"
        "5353500003000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000");
const std::string kReqSealed = bytes("05000003100000003c0010000b0000000b00000000000f007365616c65642d73"
        "747562000a06010007000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const std::string kRespSealed = bytes("0500020310000000400010000b0000000d000000000000007365616c65642d72"
        "65706c792d0000000a06030007000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const std::string kReqIntegrity = bytes("0500000310000000380010000c0000000800000000000f00706c61696e2d7374"
        "0a05000007000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const std::string kBindSpnego = bytes("05000b0310000000700020000e000000b810b810000000000100000000000100"
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800"
        "2b1048600200000009050000010000004e544c4d5353500001000000978208e2"
        "00000000000000000000000000000000");
const std::string kReqF1 = bytes("0500000110000000200000000d0000001800000000000f00667261672d312d2d");
const std::string kReqF2 = bytes("0500000010000000200000000d0000001800000000000f00667261672d322d2d");
const std::string kReqF3 = bytes("0500000210000000200000000d0000001800000000000f00667261672d332d2d");
const std::string kRespF1 = bytes("0500020110000000200000000d00000010000000000000007265706c792d312d");
const std::string kRespF2 = bytes("0500020210000000200000000d00000010000000000000007265706c792d322d");
const std::string kBindSrv = bytes("05000b03100000007400000001000000b810b810000000000200000000000100"
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800"
        "2b1048600200000001000100785734123412cdabef000123456789ac01000000"
        "045d888aeb1cc9119fe808002b10486002000000");
const std::string kBindAckSrv = bytes("05000c03100000005c00000001000000b810b810341200000d005c504950455c"
        "73727673766300000200000000000000045d888aeb1cc9119fe808002b104860"
        "0200000002000000045d888aeb1cc9119fe808002b10486002000000");
const std::string kReqSrv = bytes("050000031000000020000000020000000800000000000f007372762d73747562");
const std::string kReqSam = bytes("05000003100000002000000003000000080000000100070073616d2d73747562");
const std::string kRespSrv = bytes("0500020310000000210000000200000009000000000000007372762d7265706c"
        "79");
const std::string kBindEpm = bytes("05000b03100000004800000001000000b810b810000000000100000000000100"
        "0883afe11f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe80800"
        "2b10486002000000");
const std::string kBindAckEpm = bytes("05000c03100000003c00000001000000b810b810341200000400313335000000"
        "0100000000000000045d888aeb1cc9119fe808002b10486002000000");
const std::string kReqMap = bytes("05000003100000002d0000000200000015000000000003006d61702d72657175"
        "6573742d737475622d2d2d2d2d");
const std::string kRespMap1 = bytes("05000201100000004a0000000200000080000000000000000000000000000000"
        "0000000000000000000000000100000004000000000000000100000000000200"
        "4b0000004b0000000500");
const std::string kRespMap2 = bytes("05000202100000006600000002000000800000000000000013000dc84f324b70"
        "16d30112785a47bf6ee18803000200000013000d045d888aeb1cc9119fe80800"
        "2b10486002000200000001000b020000000100070200c20301000904000a0000"
        "020000000000");
const std::string kRespMapOne = bytes("0500020310000000980000000200000080000000000000000000000000000000"
        "0000000000000000000000000100000004000000000000000100000000000200"
        "4b0000004b000000050013000dc84f324b7016d30112785a47bf6ee188030002"
        "00000013000d045d888aeb1cc9119fe808002b10486002000200000001000b02"
        "0000000100070200c20301000904000a0000020000000000");
const std::string kRespMapSealed = bytes("0500020310000000b00010000200000080000000000000000000000000000000"
        "0000000000000000000000000100000004000000000000000100000000000200"
        "4b0000004b000000050013000dc84f324b7016d30112785a47bf6ee188030002"
        "00000013000d045d888aeb1cc9119fe808002b10486002000200000001000b02"
        "0000000100070200c20301000904000a00000200000000000a06000007000000"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    // clang-format on

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

    void bindSrvsvc(Flow &flow) { flow.client(kBindSrv).server(kBindAckSrv); }
}

TEST(DceRpcAuth, ABindWithAnNtlmsspVerifierIsLabelledAndItsTokenNamed) {
    Flow flow(50000, 135, "dce_auth_bind");
    flow.client(kBindAuth).server(kBindAckAuth).client(kAuth3);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("Bind (CallID: 10), Bind: SRVSVC (Server Service), Auth: NTLMSSP (Packet privacy)"), std::string::npos) << k[0].info;
    EXPECT_NE(k[0].info.find("NTLMSSP_NEGOTIATE"), std::string::npos) << k[0].info;
    EXPECT_NE(k[1].info.find("Bind_ack (CallID: 10), acceptance, Auth: NTLMSSP (Packet privacy)"), std::string::npos) << k[1].info;
    EXPECT_NE(k[1].info.find("NTLMSSP_CHALLENGE"), std::string::npos) << k[1].info;
    EXPECT_NE(k[2].info.find("Auth3 (CallID: 10), Auth: NTLMSSP (Packet privacy)"), std::string::npos) << k[2].info;
    EXPECT_NE(k[2].info.find("NTLMSSP_AUTH"), std::string::npos) << k[2].info;
    EXPECT_TRUE(matches("dcerpc.auth_level == 6 && dcerpc.auth_service == \"NTLMSSP\" && dcerpc.pkt_type == 11", k[0]));
    EXPECT_TRUE(matches("dcerpc.pkt_type == 16 && dcerpc.auth_level == 6", k[2]));
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Auth Verifier: NTLMSSP, Packet privacy"), nullptr);
    EXPECT_NE(find(d.fields, "Auth Type: NTLMSSP (10)"), nullptr);
    EXPECT_NE(find(d.fields, "Auth Level: Packet privacy (6)"), nullptr);
    EXPECT_NE(find(d.fields, "Auth Context ID: 7"), nullptr);
    EXPECT_NE(find(d.fields, "Auth Length: 32"), nullptr);
    EXPECT_NE(find(d.fields, "Auth Credentials (32 bytes): security token"), nullptr);
    EXPECT_NE(find(d.fields, "NTLMSSP (32 bytes): NTLMSSP_NEGOTIATE"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcAuth, ASpnegoBindAtPacketIntegrityIsLabelledToo) {
    Flow flow(50000, 135, "dce_auth_spnego");
    flow.client(kBindSpnego);
    flow.load();
    EXPECT_NE(flow.packets()[0].info.find("Auth: SPNEGO (Packet integrity)"), std::string::npos) << flow.packets()[0].info;
    EXPECT_TRUE(matches("dcerpc.auth_service == \"SPNEGO\" && dcerpc.auth_level == 5", flow.packets()[0]));
}

TEST(DceRpcAuth, TheStubDataOfAPacketPrivacyCallIsLabelledAndNeverRead) {
    Flow flow(50000, 135, "dce_auth_sealed");
    bindSrvsvc(flow);
    flow.client(kReqSealed).server(kRespSealed).client(kReqIntegrity);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[2].info.find("Request (CallID: 11), Opnum: 15, SRVSVC (Server Service), Auth: NTLMSSP (Packet privacy)"), std::string::npos) << k[2].info;
    EXPECT_TRUE(matches("dcerpc.sealed && dcerpc.auth_level == 6 && dcerpc.opnum == 15", k[2]));
    EXPECT_TRUE(matches("dcerpc.sealed && dcerpc.pkt_type == 2", k[3]));
    EXPECT_FALSE(matches("dcerpc.sealed", k[4])) << "packet integrity: the stub data is plaintext, only the signature follows";
    EXPECT_TRUE(matches("dcerpc.auth_level == 5", k[4]));
    const auto sealed = flow.details(2);
    EXPECT_NE(find(sealed.fields, "Stub data (11 bytes, sealed: packet privacy, not interpreted)"), nullptr);
    EXPECT_NE(find(sealed.fields, "Auth Padding (1 bytes)"), nullptr);
    EXPECT_NE(find(sealed.fields, "Auth Verifier: NTLMSSP, Packet privacy [stub data sealed]"), nullptr);
    EXPECT_NE(find(sealed.fields, "Auth Verifier Data (16 bytes): signature, not interpreted"), nullptr);
    const auto plain = flow.details(4);
    EXPECT_NE(find(plain.fields, "Stub data (8 bytes)"), nullptr);
    EXPECT_EQ(find(plain.fields, "Stub data (8 bytes, sealed"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcAuth, ASealedAnswerOfTheEndpointMapperIsNotMistakenForPlaintext) {
    // the same ept_map answer, once wrapped in a Response at packet privacy (sealed) and once as plaintext: only the second maps a port
    Flow sealed(50000, 135, "dce_auth_epm_sealed");
    sealed.client(kBindEpm).server(kBindAckEpm).client(kReqMap).server(kRespMapSealed);
    sealed.load();
    EXPECT_EQ(sealed.processor().sessions().dceRpcTable().endpointCount(), 0u);
    EXPECT_EQ(find(sealed.details(3).fields, "Endpoint mapper answer"), nullptr);
    EXPECT_TRUE(matches("dcerpc.sealed", sealed.packets()[3]));
    Flow plain(50000, 135, "dce_auth_epm_plain");
    plain.client(kBindEpm).server(kBindAckEpm).client(kReqMap).server(kRespMapOne);
    plain.load();
    EXPECT_EQ(plain.processor().sessions().dceRpcTable().endpointCount(), 1u);
}

TEST(DceRpcAuth, AVerifierThatDoesNotFitMarksTheCompletePduMalformedButKeepsItsName) {
    std::string bad = kReqSealed;
    bad[10] = static_cast<char>(0xff);   // auth_length larger than the fragment
    bad[11] = static_cast<char>(0x00);
    Flow flow(50000, 135, "dce_auth_bad");
    flow.client(bad);
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "DCERPC");
    EXPECT_NE(flow.packets()[0].info.find("[Malformed Packet: DCE/RPC authentication verifier does not fit in the fragment]"), std::string::npos) << flow.packets()[0].info;
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcFragments, ACallInThreeFragmentsIsReassembledInTheLastAndTheEarlierOnesPointToIt) {
    Flow flow(50000, 135, "dce_frag_call");
    bindSrvsvc(flow);
    flow.client(kReqF1).client(kReqF2).client(kReqF3).server(kRespF1).server(kRespF2);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[2].info, "Request (CallID: 13), Opnum: 15, SRVSVC (Server Service) [first fragment]");
    EXPECT_EQ(k[3].info, "Request (CallID: 13), Opnum: 15, SRVSVC (Server Service) [middle fragment]");
    EXPECT_EQ(k[4].info, "Request (CallID: 13), Opnum: 15, SRVSVC (Server Service) [last fragment] [Reassembled: 3 fragments, 24 bytes]");
    EXPECT_EQ(k[5].info, "Response (CallID: 13), SRVSVC (Server Service) [first fragment]");
    EXPECT_EQ(k[6].info, "Response (CallID: 13), SRVSVC (Server Service) [last fragment] [Reassembled: 2 fragments, 16 bytes]");
    EXPECT_TRUE(matches("dcerpc.fragment && !dcerpc.reassembled", k[2]));
    EXPECT_TRUE(matches("dcerpc.fragment && dcerpc.reassembled", k[4]));
    EXPECT_TRUE(matches("dcerpc.if_uuid == \"4b324fc8-1670-01d3-1278-5a47bf6ee188\" && dcerpc.opnum == 15", k[3])) << "the interface of the bound context";
    EXPECT_FALSE(matches("dcerpc.fragment", k[0]));
    const auto first = flow.details(2), last = flow.details(4), reply = flow.details(6);
    EXPECT_NE(find(first.fields, "[Reassembled in frame 5]"), nullptr);
    EXPECT_NE(find(flow.details(3).fields, "[Reassembled in frame 5]"), nullptr);
    EXPECT_NE(find(last.fields, "[Reassembled stub data: 24 bytes in 3 fragments, frames #3, #4, #5]"), nullptr);
    EXPECT_NE(find(reply.fields, "[Reassembled stub data: 16 bytes in 2 fragments, frames #6, #7]"), nullptr);
    EXPECT_NE(find(reply.fields, "[Request in frame 3]"), nullptr) << "the first fragment of the request";
    EXPECT_NE(find(reply.fields, "[Operation of the request: 15]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcFragments, ALastFragmentWithoutItsFirstIsNamedAndNotReassembled) {
    Flow flow(50000, 135, "dce_frag_orphan");
    flow.client(kReqF3);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info.find("Reassembled"), std::string::npos);
    EXPECT_NE(find(flow.details(0).fields, "[The first fragment of this call was not captured"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcFragments, ACallIdThatStartsOverForgetsTheUnfinishedChain) {
    Flow flow(50000, 135, "dce_frag_restart");
    flow.client(kReqF1).client(kReqF1).client(kReqF3);
    flow.load();
    EXPECT_NE(flow.packets()[2].info.find("[Reassembled: 2 fragments, 16 bytes]"), std::string::npos) << flow.packets()[2].info;
    EXPECT_EQ(find(flow.details(0).fields, "[Reassembled in frame"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "[Reassembled in frame 3]"), nullptr);
}

TEST(DceRpcEpm, AnAnswerSplitOverTwoFragmentsListsItsTowers) {
    Flow flow(50000, 135, "dce_epm_towers");
    flow.client(kBindEpm).server(kBindAckEpm).client(kReqMap).server(kRespMap1).server(kRespMap2);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[2].info, "Request (CallID: 2), Opnum: 3, EPM (Endpoint Mapper)");
    EXPECT_NE(k[4].info.find("[last fragment] [Reassembled: 2 fragments, 128 bytes]"), std::string::npos) << k[4].info;
    const auto d = flow.details(4);
    ASSERT_NE(find(d.fields, "Endpoint mapper answer: 1 tower(s)"), nullptr);
    EXPECT_NE(find(d.fields, "SRVSVC (Server Service) v3.0: ncacn_ip_tcp 10.0.0.2:49667"), nullptr);
    EXPECT_EQ(find(flow.details(3).fields, "Endpoint mapper answer"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcEpm, ASingleResponseWithoutABindIsReadOnPort135) {
    Flow flow(50000, 135, "dce_epm_single");
    flow.client(kReqMap).server(kRespMapOne);
    flow.load();
    EXPECT_NE(find(flow.details(1).fields, "Endpoint mapper answer: 1 tower(s)"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "[Interface: EPM (Endpoint Mapper) (assumed from the endpoint, no Bind)]"), nullptr);
    EXPECT_EQ(flow.packets()[0].info, "Request (CallID: 2), Opnum: 3") << "an assumed interface is not put in the Info column";
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcFlows, ARequestOnAContextABindRejectedSaysSo) {
    Flow flow(50000, 135, "dce_ctx_rejected");
    bindSrvsvc(flow);
    flow.client(kReqSam);
    flow.load();
    EXPECT_NE(find(flow.details(2).fields, "[Context 1 was not accepted by a Bind in the capture]"), nullptr);
    EXPECT_EQ(flow.packets()[2].info.find("Auth"), std::string::npos);
}

TEST(DceRpcFlows, TheBudgetRunningOutIsSaidInTheTree) {
    Flow flow(50000, 135, "dce_budget");
    flow.processor().sessions().setMaxMemoryPerTable(600);
    bindSrvsvc(flow);
    flow.client(kReqF1).client(kReqF2).client(kReqF3).server(kRespF1).server(kRespF2).client(kReqSrv).server(kRespSrv);
    flow.load();
    EXPECT_TRUE(flow.processor().sessions().isTableStateLost("dcerpc"));
    bool said = false;
    for (size_t i = 0; i < flow.packets().size(); ++i) if (find(flow.details(i).fields, "[DCE/RPC session state lost")) said = true;
    EXPECT_TRUE(said);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcFlows, EveryNewPduSurvivesTruncationAndMutation) {
    for (const std::string *m: {&kBindAuth, &kBindAckAuth, &kAuth3, &kReqSealed, &kRespSealed, &kReqIntegrity, &kBindSpnego, &kReqF1, &kReqF2, &kReqF3, &kRespF1,
                                &kBindSrv, &kBindAckSrv, &kReqSrv, &kRespSrv, &kBindEpm, &kBindAckEpm, &kReqMap, &kRespMap1, &kRespMap2, &kRespMapOne, &kRespMapSealed}) {
        appflow::sweepPayload(*m, 135, 0x4a53);
    }
}

// DCE/RPC on the ports the endpoint mapper announced: the answer of ept_map / ept_lookup (a tower with a TCP or UDP port and an IP
// address, C706 appendix L) puts the host and port in the session table from that packet on; a later connection to the port is
// DCE/RPC even though no port number says so, with the interface of the mapping when no Bind named one. Earlier packets, other
// ports and ports shared by two interfaces behave as described in each test. Vectors: scratchpad g12c/co.py, cl.py, dce.py (struct).
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
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
const std::string kRespMapOne = bytes("0500020310000000980000000200000080000000000000000000000000000000"
        "0000000000000000000000000100000004000000000000000100000000000200"
        "4b0000004b000000050013000dc84f324b7016d30112785a47bf6ee188030002"
        "00000013000d045d888aeb1cc9119fe808002b10486002000200000001000b02"
        "0000000100070200c20301000904000a0000020000000000");
const std::string kReqLookup = bytes("050000031000000023000000030000000b000000000002006c6f6f6b75702d73"
        "747562");
const std::string kRespLookup = bytes("0500020310000000a00100000300000088010000000000000000000000000000"
        "0000000000000000000000000300000008000000000000000300000000000000"
        "0000000000000000000000000000020000000000070000005365727665720000"
        "0000000000000000000000000000000004000200000000000400000053414d00"
        "0000000000000000000000000000000008000200000000000100000000000000"
        "4b0000004b000000050013000dc84f324b7016d30112785a47bf6ee188030002"
        "00000013000d045d888aeb1cc9119fe808002b10486002000200000001000b02"
        "0000000100070200c20301000904000a000002004b0000004b00000005001300"
        "0d785734123412cdabef000123456789ac01000200000013000d045d888aeb1c"
        "c9119fe808002b10486002000200000001000b020000000100070200c2030100"
        "0904000a000002004b0000004b000000050013000dc84f324b7016d30112785a"
        "47bf6ee18803000200000013000d045d888aeb1cc9119fe808002b1048600200"
        "0200000001000b020000000100070200c22401000904000a0000020000000000");
const std::string kClReq = bytes("040020001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "050000000f00ffffffff0c0000000002636c2d737475622d626f6479");
const std::string kClEpmReq = bytes("0400200010000001000000000000000000000000000000000883afe11f5dc911"
        "91a408002b14a0faccddeeffaabb889977665544332211000000005f03000000"
        "010000000300ffffffff0800000000026d61702d73747562");
const std::string kClEpmResp = bytes("0402200010000001000000000000000000000000000000000883afe11f5dc911"
        "91a408002b14a0faccddeeffaabb889977665544332211000000005f03000000"
        "010000000300ffffffffd8000000000200000000000000000000000000000000"
        "000000000200000004000000000000000200000000000200040002004b000000"
        "4b000000050013000dc84f324b7016d30112785a47bf6ee18803000200000013"
        "000d045d888aeb1cc9119fe808002b10486002000200000001000a0200000001"
        "00080200c22401000904000a000002004b0000004b000000050013000dc84f32"
        "4b7016d30112785a47bf6ee18803000200000013000d045d888aeb1cc9119fe8"
        "08002b10486002000200000001000b020000000100070200c20301000904000a"
        "0000020000000000");
    // clang-format on

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }

    void epmExchange(Flow &flow) { flow.on(50000, 135).client(kBindEpm).server(kBindAckEpm).client(kReqMap).server(kRespMapOne); }
}

TEST(DceRpcPorts, ALaterConnectionToAnAnnouncedPortIsDceRpc) {
    Flow flow(50000, 135, "dce_ports_tcp");
    flow.on(50002, 49667).client(kReqSrv);   // before the answer: nobody knows the port
    epmExchange(flow);
    flow.on(50001, 49667).client(kBindSrv).server(kBindAckSrv).client(kReqSrv).server(kRespSrv);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "TCP") << "the port was not announced yet: " << k[0].info;
    EXPECT_EQ(k[1].protocol, "DCERPC");
    EXPECT_EQ(k[5].protocol, "DCERPC");
    EXPECT_EQ(k[5].info, "Bind (CallID: 1), Bind: SRVSVC (Server Service), SAMR (Security Account Manager)");
    EXPECT_EQ(k[6].info, "Bind_ack (CallID: 1), acceptance, provider-rejection");
    EXPECT_EQ(k[7].info, "Request (CallID: 2), Opnum: 15, SRVSVC (Server Service)");
    EXPECT_EQ(k[8].info, "Response (CallID: 2), SRVSVC (Server Service)");
    flow.expectReplayEqualsLoad();
    EXPECT_EQ(flow.details(0).protocol, "TCP") << "Replay decodes the early packet as it was loaded";
}

TEST(DceRpcPorts, WithoutABindTheInterfaceOfTheMappingIsAssumed) {
    Flow flow(50000, 135, "dce_ports_assumed");
    epmExchange(flow);
    flow.on(50001, 49667).client(kReqSam).server(kRespSrv);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[4].protocol, "DCERPC");
    EXPECT_EQ(k[4].info, "Request (CallID: 3), Opnum: 7") << "an assumed interface stays out of the Info column";
    EXPECT_NE(find(flow.details(4).fields, "[Interface: SRVSVC (Server Service) (assumed from the endpoint, no Bind)]"), nullptr);
    EXPECT_NE(find(flow.details(5).fields, "[Interface: SRVSVC (Server Service) (assumed from the endpoint, no Bind)]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPorts, OtherPortsStayTcp) {
    Flow flow(50000, 135, "dce_ports_other");
    epmExchange(flow);
    flow.on(50004, 49999).client(kReqSrv);
    flow.load();
    EXPECT_EQ(flow.packets()[4].protocol, "TCP");
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPorts, ANonDceMessageOnAnAnnouncedPortStaysTcp) {
    Flow flow(50000, 135, "dce_ports_garbage");
    epmExchange(flow);
    flow.on(50004, 49667).client(bytes("474554202f20485454502f312e310d0a0d0a"));
    flow.load();
    EXPECT_NE(flow.packets()[4].protocol, "DCERPC");
}

TEST(DceRpcPorts, APortTwoInterfacesShareIsDceButTheInterfaceIsNotGuessed) {
    Flow flow(50000, 135, "dce_ports_ambiguous");
    flow.on(50000, 135).client(kBindEpm).server(kBindAckEpm).client(kReqLookup).server(kRespLookup);
    flow.on(50001, 49667).client(kReqSam);
    flow.on(50002, 49700).client(kReqSam);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(find(flow.details(3).fields, "Endpoint mapper answer: 3 tower(s)"), nullptr);
    EXPECT_EQ(k[4].protocol, "DCERPC") << "SRVSVC and SAMR both listen on 49667";
    EXPECT_EQ(find(flow.details(4).fields, "[Interface:"), nullptr);
    EXPECT_EQ(k[5].protocol, "DCERPC");
    EXPECT_NE(find(flow.details(5).fields, "[Interface: SRVSVC (Server Service) (assumed"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPorts, ADatagramToAnAnnouncedUdpPortIsConnectionlessDceRpc) {
    Flow flow(50000, 135, "dce_ports_udp");
    flow.asUdp();
    flow.on(50002, 49700).client(kClReq);   // before the answer
    flow.on(50000, 135).client(kClEpmReq).server(kClEpmResp);
    flow.on(50001, 49700).client(kClReq);
    flow.on(50003, 49701).client(kClReq);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "UDP");
    EXPECT_EQ(k[3].protocol, "DCERPC");
    EXPECT_EQ(k[3].info, "Request (Seq: 5), Opnum: 15, SRVSVC (Server Service)");
    EXPECT_EQ(k[4].protocol, "UDP");
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPorts, ThePortMapAnswersFromTheServerAddressOfTheEndpointMapper) {
    Flow flow(50000, 135, "dce_ports_server");
    epmExchange(flow);
    flow.load();
    const auto &sessions = flow.processor().sessions();
    ASSERT_NE(sessions.dceRpcEndpoint("10.0.0.2", 49667, false, 4), nullptr);
    EXPECT_EQ(sessions.dceRpcEndpoint("10.0.0.2", 49667, false, 3), nullptr) << "valid from the packet that carried the answer on";
    EXPECT_EQ(sessions.dceRpcEndpoint("10.0.0.1", 49667, false, 9), nullptr) << "the client is not the server";
}

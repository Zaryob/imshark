// DCE/RPC connectionless PDUs (RPC version 4, C706 12.4) over UDP: the 80 byte header (rpc_vers, ptype, flags1, flags2, drep[3],
// serial_hi, object, if_id, act_id, server_boot, if_vers, seqnum, opnum, ihint, ahint, len, fragnum, auth_proto, serial_lo) and the
// body, packed with Python's struct module and uuid.UUID(...).bytes_le / .bytes (scratchpad g12c/cl.py; the endpoint mapper answer
// by dce.py). The port 135 registration, fragments arriving in any order, the status of fault / reject, fack, a PDU with an
// authentication protocol (its body is not told apart into stub data and verifier), big-endian data representation.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/dcerpc.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
const std::string kClReq = bytes("040020001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "050000000f00ffffffff0c0000000002636c2d737475622d626f6479");
const std::string kClResp = bytes("040220001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "050000000f00ffffffff080000000002636c2d7265706c79");
const std::string kClFault = bytes("040300001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "060000000f00ffffffff0400000000020300011c");
const std::string kClPing = bytes("040100001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "070000000f00ffffffff000000000002");
const std::string kClFack = bytes("040900001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "070000000f00ffffffff10000000000201000800c0050000c005000003000000");
const std::string kClReqBe = bytes("0400200000000001000000000000000000000000000000004b324fc8167001d3"
        "12785a47bf6ee18800112233445566778899aabbccddeeff5f00000000000003"
        "000000090102ffffffff00070000000262652d626f6479");
const std::string kClF0 = bytes("040004001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "080000000f00ffffffff080000000002667261672d302d2d");
const std::string kClF1 = bytes("040004001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "080000000f00ffffffff080001000002667261672d312d2d");
const std::string kClF2 = bytes("040006001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "080000000f00ffffffff060002000002667261672d32");
const std::string kClAuth = bytes("040000001000000100000000000000000000000000000000c84f324b7016d301"
        "12785a47bf6ee18833221100554477668899aabbccddeeff0000005f03000000"
        "0a0000000f00ffffffff280000000a0201010101010101010101010101010101"
        "010101010101010101010101010101010101010101010101");
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

TEST(DceRpcCl, RequestAndResponseCarryTheirInterfaceInTheHeader) {
    Flow flow(50000, 135, "dce_cl_basic");
    flow.asUdp().client(kClReq).server(kClResp);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "DCERPC");
    EXPECT_EQ(k[0].info, "Request (Seq: 5), Opnum: 15, SRVSVC (Server Service)");
    EXPECT_EQ(k[1].info, "Response (Seq: 5), SRVSVC (Server Service)");
    EXPECT_TRUE(matches("dcerpc && dcerpc.pkt_type == 0 && dcerpc.opnum == 15 && dcerpc.if_uuid == \"4b324fc8-1670-01d3-1278-5a47bf6ee188\"", k[0]));
    EXPECT_FALSE(matches("dcerpc.cn_call_id == 5", k[0])) << "a connectionless PDU has no connection-oriented call id";
    EXPECT_FALSE(matches("dcerpc.opnum == 15", k[1])) << "a response has no opnum";
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "DCE/RPC (Request, connectionless)"), nullptr);
    EXPECT_NE(find(d.fields, "Version: 4"), nullptr);
    EXPECT_NE(find(d.fields, "Flags1: 0x20 Idempotent"), nullptr);
    EXPECT_NE(find(d.fields, "Interface: SRVSVC (Server Service) v3.0"), nullptr);
    EXPECT_NE(find(d.fields, "Activity: 00112233-4455-6677-8899-aabbccddeeff"), nullptr);
    EXPECT_NE(find(d.fields, "Sequence Number: 5"), nullptr);
    EXPECT_NE(find(d.fields, "Operation: 15"), nullptr);
    EXPECT_NE(find(d.fields, "Body Length: 12"), nullptr);
    EXPECT_NE(find(d.fields, "Stub data (12 bytes)"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "[Request in frame 1]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcCl, FaultRejectFackAndPingAreRead) {
    Flow flow(50000, 135, "dce_cl_misc");
    flow.asUdp().client(kClPing).server(kClFault).server(kClFack);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Ping (Seq: 7), SRVSVC (Server Service)");
    EXPECT_EQ(k[1].info, "Fault (Seq: 6), Status: 0x1c010003, SRVSVC (Server Service)");
    EXPECT_NE(find(flow.details(1).fields, "Fault Status: 0x1c010003"), nullptr);
    EXPECT_EQ(k[2].info, "Fack (Seq: 7), SRVSVC (Server Service)");
    const auto d = flow.details(2);
    EXPECT_NE(find(d.fields, "Window Size: 8"), nullptr);
    EXPECT_NE(find(d.fields, "Max TPDU: 1472"), nullptr);
    EXPECT_NE(find(d.fields, "Serial Number: 3"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcCl, ABigEndianDataRepresentationIsFollowed) {
    Flow flow(50000, 135, "dce_cl_be");
    flow.asUdp().client(kClReqBe);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Request (Seq: 9), Opnum: 258, SRVSVC (Server Service)");
    EXPECT_NE(find(flow.details(0).fields, "Data Representation: big-endian"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "Interface: SRVSVC (Server Service) v3.0"), nullptr) << "the UUID fields follow the data representation too";
}

TEST(DceRpcCl, FragmentsArrivingOutOfOrderAreReassembledWhenTheMissingOneComes) {
    Flow flow(50000, 135, "dce_cl_frag");
    flow.asUdp().client(kClF0).client(kClF2).client(kClF1);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Request (Seq: 8), Opnum: 15, SRVSVC (Server Service) [fragment 0]");
    EXPECT_EQ(k[1].info, "Request (Seq: 8), Opnum: 15, SRVSVC (Server Service) [fragment 2, last]");
    EXPECT_EQ(k[2].info, "Request (Seq: 8), Opnum: 15, SRVSVC (Server Service) [fragment 1] [Reassembled: 3 fragments, 22 bytes]");
    EXPECT_TRUE(matches("dcerpc.fragment && dcerpc.reassembled", k[2]));
    EXPECT_TRUE(matches("dcerpc.fragment && !dcerpc.reassembled", k[1]));
    EXPECT_NE(find(flow.details(2).fields, "[Reassembled stub data: 22 bytes in 3 fragments, frames #1, #3, #2]"), nullptr) << "in fragment order";
    EXPECT_NE(find(flow.details(0).fields, "[Reassembled in frame 3]"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "[Reassembled in frame 3]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcCl, ARepeatedFragmentIsNotCountedTwice) {
    Flow flow(50000, 135, "dce_cl_dup");
    flow.asUdp().client(kClF0).client(kClF0).client(kClF2).client(kClF1);
    flow.load();
    EXPECT_NE(find(flow.details(1).fields, "[Fragment 0 was seen before"), nullptr);
    EXPECT_NE(flow.packets()[3].info.find("[Reassembled: 3 fragments, 22 bytes]"), std::string::npos) << flow.packets()[3].info;
    EXPECT_EQ(find(flow.details(1).fields, "[Reassembled in frame"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcCl, ABodyBehindAnAuthenticationProtocolIsLabelledAndNotInterpreted) {
    Flow flow(50000, 135, "dce_cl_auth");
    flow.asUdp().client(kClAuth);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Request (Seq: 10), Opnum: 15, SRVSVC (Server Service), Auth: NTLMSSP");
    EXPECT_TRUE(matches("dcerpc.sealed && dcerpc.auth_service == \"NTLMSSP\"", flow.packets()[0]));
    EXPECT_NE(find(flow.details(0).fields, "Auth Protocol: NTLMSSP (10)"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "Body (40 bytes, stub data and NTLMSSP verifier together, not interpreted)"), nullptr);
}

TEST(DceRpcCl, TheEndpointMapperAnswerOverUdpListsItsTowers) {
    Flow flow(50000, 135, "dce_cl_epm");
    flow.asUdp().client(kClEpmReq).server(kClEpmResp);
    flow.load();
    const auto d = flow.details(1);
    ASSERT_NE(find(d.fields, "Endpoint mapper answer: 2 tower(s)"), nullptr);
    EXPECT_NE(find(d.fields, "SRVSVC (Server Service) v3.0: ncadg_ip_udp 10.0.0.2:49700"), nullptr);
    EXPECT_NE(find(d.fields, "SRVSVC (Server Service) v3.0: ncacn_ip_tcp 10.0.0.2:49667"), nullptr);
    EXPECT_EQ(flow.processor().sessions().dceRpcTable().endpointCount(), 2u);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcCl, ADatagramThatIsNotAVersion4PduStaysUdp) {
    Flow flow(50000, 135, "dce_cl_not");
    flow.asUdp().client(bytes("0500000310000000200000000200000008000000")).client(bytes("0402")).client(std::string(100, 'x'));
    flow.load();
    for (const auto &p: flow.packets()) EXPECT_EQ(p.protocol, "UDP") << p.info;
}

TEST(DceRpcCl, DecodeAsMakesAnyUdpPortDce) {
    Flow plain(50000, 7777, "dce_cl_decode_as_plain");
    plain.asUdp().client(kClReq);
    plain.load();
    EXPECT_EQ(plain.packets()[0].protocol, "UDP") << "port 7777 is nothing in particular";
    dissect::Registry registry = dissect::Registry::builtin();
    std::string error;
    ASSERT_TRUE(registry.decodeAs(false, 7777, "DCERPC", &error)) << error;
    core::FileProcessor fp(registry);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("dce_cl_decode_as.pcap", support::pcapBytes({support::udpPacket("0a000001", "0a000002", "c350", "1e61", kClReq)}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    EXPECT_EQ(packets[0].protocol, "DCERPC");
    EXPECT_EQ(packets[0].info, "Request (Seq: 5), Opnum: 15, SRVSVC (Server Service)");
    std::remove(path.c_str());
}

TEST(DceRpcCl, EveryPduSurvivesTruncationAndMutation) {
    for (const std::string *m: {&kClReq, &kClResp, &kClFault, &kClPing, &kClFack, &kClReqBe, &kClF0, &kClF1, &kClF2, &kClAuth, &kClEpmReq, &kClEpmResp}) {
        appflow::sweepDatagram(*m, 135, 0x434c);
    }
}

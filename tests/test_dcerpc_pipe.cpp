// DCE/RPC inside SMB2 named pipes: the PDU is the data of a Write request, a Read response or an IOCTL FSCTL_PIPE_TRANSCEIVE request /
// response on a FileId the session table (smb2_session.h) knows as an open file of an IPC$ share. One TCP connection, built by the
// independent Python encoders scratchpad g12c/smbpipe.py ([MS-SMB2] layouts through G12b's smbvec.py, PDUs through co.py): the IPC$ tree,
// \srvsvc opened, Bind by Write and Bind_ack by Read, a call by FSCTL_PIPE_TRANSCEIVE, a request split over three Writes and its
// response over two Reads, \epmapper (ept_map by FSCTL_PIPE_TRANSCEIVE announcing 10.0.0.2:49667), the same request bytes written to a
// file of a disk share (not a pipe), and bytes written to the pipe that are no PDU.
#include <gtest/gtest.h>

#include <random>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
const std::string kTreeIpc = bytes("00000060fe534d42400001000000000003000100000000000000000001000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "0000000009000000480018005c005c00660069006c00650073005c0049005000"
        "43002400");
const std::string kTreeIpcResp = bytes("00000050fe534d42400001000000000003000100010000000000000001000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000100002000000000030000000ff011f00");
const std::string kOpenSrv = bytes("00000084fe534d42400001000000000005000100000000000000000002000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078000c00000000000000000073007200"
        "7600730076006300");
const std::string kOpenSrvResp = bytes("00000099fe534d42400001000000000005000100010000000000000002000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "0000000010000000000000001100000000000000000000000000000000");
const std::string kWriteBind = bytes("000000e4fe534d42400001000000000009000100000000000000000003000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031007000740000000000000000000000100000000000000011000000"
        "000000000000000000000000000000000000000005000b031000000074000000"
        "01000000b810b810000000000200000000000100c84f324b7016d30112785a47"
        "bf6ee18803000000045d888aeb1cc9119fe808002b1048600200000001000100"
        "785734123412cdabef000123456789ac01000000045d888aeb1cc9119fe80800"
        "2b10486002000000");
const std::string kWriteBindResp = bytes("00000050fe534d42400001000000000009000100010000000000000003000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011000000740000000000000000000000");
const std::string kReadAck = bytes("00000071fe534d42400001000000000008000100000000000000000004000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031000000001000000000000000000000100000000000000011000000"
        "000000000000000000000000000000000000000000");
const std::string kReadAckResp = bytes("000000acfe534d42400001000000000008000100010000000000000004000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000110050005c000000000000000000000005000c03100000005c000000"
        "01000000b810b810341200000d005c504950455c737276737663000002000000"
        "00000000045d888aeb1cc9119fe808002b1048600200000002000000045d888a"
        "eb1cc9119fe808002b10486002000000");
const std::string kCallReq = bytes("00000098fe534d4240000100000000000b000100000000000000000005000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003900000017c011001000000000000000110000000000000078000000"
        "2000000000000000000000000000000000100000010000000000000005000003"
        "1000000020000000020000000800000000000f007372762d73747562");
const std::string kCallResp = bytes("00000091fe534d4240000100000000000b000100010000000000000005000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003100000017c011001000000000000000110000000000000000000000"
        "0000000070000000210000000000000000000000050002031000000021000000"
        "0200000009000000000000007372762d7265706c79");
const std::string kFrag1 = bytes("00000090fe534d42400001000000000009000100000000000000000006000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031007000200000000000000000000000100000000000000011000000"
        "0000000000000000000000000000000000000000050000011000000020000000"
        "0d0000001800000000000f00667261672d312d2d");
const std::string kFrag1Resp = bytes("00000050fe534d42400001000000000009000100010000000000000006000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011000000200000000000000000000000");
const std::string kFrag2 = bytes("00000090fe534d42400001000000000009000100000000000000000007000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031007000200000000000000000000000100000000000000011000000"
        "0000000000000000000000000000000000000000050000001000000020000000"
        "0d0000001800000000000f00667261672d322d2d");
const std::string kFrag2Resp = bytes("00000050fe534d42400001000000000009000100010000000000000007000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011000000200000000000000000000000");
const std::string kFrag3 = bytes("00000090fe534d42400001000000000009000100000000000000000008000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031007000200000000000000000000000100000000000000011000000"
        "0000000000000000000000000000000000000000050000021000000020000000"
        "0d0000001800000000000f00667261672d332d2d");
const std::string kFrag3Resp = bytes("00000050fe534d42400001000000000009000100010000000000000008000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011000000200000000000000000000000");
const std::string kReadR1 = bytes("00000071fe534d42400001000000000008000100000000000000000009000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031000000001000000000000000000000100000000000000011000000"
        "000000000000000000000000000000000000000000");
const std::string kReadR1Resp = bytes("00000070fe534d42400001000000000008000100010000000000000009000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011005000200000000000000000000000050002011000000020000000"
        "0d00000010000000000000007265706c792d312d");
const std::string kReadR2 = bytes("00000071fe534d4240000100000000000800010000000000000000000a000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000031000000001000000000000000000000100000000000000011000000"
        "000000000000000000000000000000000000000000");
const std::string kReadR2Resp = bytes("00000070fe534d4240000100000000000800010001000000000000000a000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000011005000200000000000000000000000050002021000000020000000"
        "0d00000010000000000000007265706c792d322d");
const std::string kOpenEpm = bytes("00000088fe534d4240000100000000000500010000000000000000000b000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078001000000000000000000065007000"
        "6d0061007000700065007200");
const std::string kOpenEpmResp = bytes("00000099fe534d4240000100000000000500010001000000000000000b000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "0000000020000000000000002100000000000000000000000000000000");
const std::string kEpmBind = bytes("000000c0fe534d4240000100000000000b00010000000000000000000c000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003900000017c011002000000000000000210000000000000078000000"
        "4800000000000000000000000000000000100000010000000000000005000b03"
        "100000004800000001000000b810b8100000000001000000000001000883afe1"
        "1f5dc91191a408002b14a0fa03000000045d888aeb1cc9119fe808002b104860"
        "02000000");
const std::string kEpmBindResp = bytes("000000acfe534d4240000100000000000b00010001000000000000000c000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003100000017c011002000000000000000210000000000000000000000"
        "00000000700000003c000000000000000000000005000c03100000003c000000"
        "01000000b810b8103412000004003133350000000100000000000000045d888a"
        "eb1cc9119fe808002b10486002000000");
const std::string kEpmMap = bytes("000000a5fe534d4240000100000000000b00010000000000000000000d000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003900000017c011002000000000000000210000000000000078000000"
        "2d00000000000000000000000000000000100000010000000000000005000003"
        "100000002d0000000200000015000000000003006d61702d726571756573742d"
        "737475622d2d2d2d2d");
const std::string kEpmMapResp = bytes("00000108fe534d4240000100000000000b00010001000000000000000d000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "000000003100000017c011002000000000000000210000000000000000000000"
        "0000000070000000980000000000000000000000050002031000000098000000"
        "0200000080000000000000000000000000000000000000000000000000000000"
        "01000000040000000000000001000000000002004b0000004b00000005001300"
        "0dc84f324b7016d30112785a47bf6ee18803000200000013000d045d888aeb1c"
        "c9119fe808002b10486002000200000001000b020000000100070200c2030100"
        "0904000a0000020000000000");
const std::string kTreeDisk = bytes("00000062fe534d4240000100000000000300010000000000000000000e000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "000000000900000048001a005c005c00660069006c00650073005c0073006800"
        "610072006500");
const std::string kTreeDiskResp = bytes("00000050fe534d4240000100000000000300010001000000000000000e000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000100001000000000030000000ff011f00");
const std::string kOpenDisk = bytes("00000082fe534d4240000100000000000500010000000000000000000f000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078000a00000000000000000078002e00"
        "620069006e00");
const std::string kOpenDiskResp = bytes("00000099fe534d4240000100000000000500010001000000000000000f000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "0000000030000000000000003100000000000000000000000000000000");
const std::string kWriteDisk = bytes("00000090fe534d42400001000000000009000100000000000000000010000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000031007000200000000000000000000000300000000000000031000000"
        "0000000000000000000000000000000000000000050000031000000020000000"
        "020000000800000000000f007372762d73747562");
const std::string kWriteDiskResp = bytes("00000050fe534d42400001000000000009000100010000000000000010000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000011000000200000000000000000000000");
const std::string kWriteJunk = bytes("0000007afe534d42400001000000000009000100000000000000000011000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000310070000a0000000000000000000000100000000000000011000000"
        "000000000000000000000000000000000000000068656c6c6f2070697065");
const std::string kWriteJunkResp = bytes("00000050fe534d42400001000000000009000100010000000000000011000000"
        "0000000000000000090000000100100000000000000000000000000000000000"
        "00000000110000000a0000000000000000000000");
const std::string kBindSrv = bytes("05000b03100000007400000001000000b810b810000000000200000000000100"
        "c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe80800"
        "2b1048600200000001000100785734123412cdabef000123456789ac01000000"
        "045d888aeb1cc9119fe808002b10486002000000");
const std::string kBindAckSrv = bytes("05000c03100000005c00000001000000b810b810341200000d005c504950455c"
        "73727673766300000200000000000000045d888aeb1cc9119fe808002b104860"
        "0200000002000000045d888aeb1cc9119fe808002b10486002000000");
const std::string kReqSrv = bytes("050000031000000020000000020000000800000000000f007372762d73747562");

    // clang-format on
    struct Msg { bool client; const std::string *data; };
    const Msg kScenario[] = {
        {true, &kTreeIpc}, {false, &kTreeIpcResp}, {true, &kOpenSrv}, {false, &kOpenSrvResp}, {true, &kWriteBind}, {false, &kWriteBindResp},
        {true, &kReadAck}, {false, &kReadAckResp}, {true, &kCallReq}, {false, &kCallResp}, {true, &kFrag1}, {false, &kFrag1Resp},
        {true, &kFrag2}, {false, &kFrag2Resp}, {true, &kFrag3}, {false, &kFrag3Resp}, {true, &kReadR1}, {false, &kReadR1Resp},
        {true, &kReadR2}, {false, &kReadR2Resp}, {true, &kOpenEpm}, {false, &kOpenEpmResp}, {true, &kEpmBind}, {false, &kEpmBindResp},
        {true, &kEpmMap}, {false, &kEpmMapResp}, {true, &kTreeDisk}, {false, &kTreeDiskResp}, {true, &kOpenDisk}, {false, &kOpenDiskResp},
        {true, &kWriteDisk}, {false, &kWriteDiskResp}, {true, &kWriteJunk}, {false, &kWriteJunkResp},
    };

    void addScenario(Flow &flow) {
        for (const Msg &m: kScenario) { if (m.client) flow.client(*m.data); else flow.server(*m.data); }
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr << ": " << f.error.message;
        return f.ok && f.filter.matches(p);
    }

    bool has(const std::string &text, const std::string &part) { return text.find(part) != std::string::npos; }
}

TEST(DceRpcPipe, BindWrittenAndBindAckReadAreDecodedAndTiedToTheInterface) {
    Flow flow(50000, 445, "dce_pipe_bind");
    addScenario(flow);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[4].protocol, "SMB2") << "the packet stays an SMB2 packet";
    EXPECT_TRUE(has(k[4].info, "Write Request, Len: 116, Off: 0, File: srvsvc, DCERPC Bind (CallID: 1), Bind: SRVSVC (Server Service), SAMR (Security Account Manager)")) << k[4].info;
    EXPECT_TRUE(has(k[7].info, "Read Response, STATUS_SUCCESS, Len: 92, File: srvsvc, DCERPC Bind_ack (CallID: 1), acceptance, provider-rejection")) << k[7].info;
    EXPECT_TRUE(matches("dcerpc && dcerpc.pkt_type == 11 && smb2.pipe && smb2.file == \"srvsvc\"", k[4]));
    EXPECT_TRUE(matches("dcerpc.pkt_type == 12 && smb2.cmd == 8", k[7]));
    EXPECT_FALSE(matches("dcerpc", k[5])) << "the Write response carries nothing";
    EXPECT_FALSE(matches("dcerpc", k[6])) << "the Read request carries nothing";
    const auto d = flow.details(4);
    EXPECT_NE(find(d.fields, "SMB2 (Write Request)"), nullptr);
    EXPECT_NE(find(d.fields, "DCE/RPC (Bind)"), nullptr);
    EXPECT_NE(find(d.fields, "Context 1: SAMR (Security Account Manager) v1.0"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, ACallThroughPipeTransceiveFindsItsInterfaceInTheBindOfTheSamePipe) {
    Flow flow(50000, 445, "dce_pipe_call");
    addScenario(flow);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_TRUE(has(k[8].info, "DCERPC Request (CallID: 2), Opnum: 15, SRVSVC (Server Service)")) << k[8].info;
    EXPECT_TRUE(has(k[9].info, "DCERPC Response (CallID: 2), SRVSVC (Server Service)")) << k[9].info;
    EXPECT_TRUE(matches("dcerpc.opnum == 15 && dcerpc.pkt_type == 0 && dcerpc.if_uuid == \"4b324fc8-1670-01d3-1278-5a47bf6ee188\"", k[8]));
    EXPECT_TRUE(matches("dcerpc.pkt_type == 2 && !(dcerpc.opnum == 15)", k[9]));
    EXPECT_FALSE(matches("dcerpc.cn_call_id == 2", k[8])) << "the call id of a PDU in an SMB2 packet is not kept";
    EXPECT_NE(find(flow.details(9).fields, "[Request in frame 9]"), nullptr);
    EXPECT_NE(find(flow.details(9).fields, "[Operation of the request: 15]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, AFragmentedCallOverThreeWritesAndTwoReadsIsReassembled) {
    Flow flow(50000, 445, "dce_pipe_frag");
    addScenario(flow);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_TRUE(has(k[10].info, "[first fragment]")) << k[10].info;
    EXPECT_TRUE(has(k[12].info, "[middle fragment]")) << k[12].info;
    EXPECT_TRUE(has(k[14].info, "[last fragment] [Reassembled: 3 fragments, 24 bytes]")) << k[14].info;
    EXPECT_TRUE(has(k[17].info, "DCERPC Response (CallID: 13), SRVSVC (Server Service) [first fragment]")) << k[17].info;
    EXPECT_TRUE(has(k[19].info, "[last fragment] [Reassembled: 2 fragments, 16 bytes]")) << k[19].info;
    EXPECT_NE(find(flow.details(14).fields, "[Reassembled stub data: 24 bytes in 3 fragments, frames #11, #13, #15]"), nullptr);
    EXPECT_NE(find(flow.details(10).fields, "[Reassembled in frame 15]"), nullptr);
    EXPECT_NE(find(flow.details(19).fields, "[Reassembled stub data: 16 bytes in 2 fragments, frames #18, #20]"), nullptr);
    EXPECT_NE(find(flow.details(19).fields, "[Request in frame 11]"), nullptr) << "the first fragment of the request";
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, TheEndpointMapperOverAPipeAnnouncesAPortLaterConnectionsUse) {
    Flow flow(50000, 445, "dce_pipe_epm");
    addScenario(flow);
    // a later TCP connection to the announced port: srvsvc without a Bind in front, then with one
    flow.on(50001, 49667).client(kReqSrv).client(kBindSrv).server(kBindAckSrv);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(find(flow.details(25).fields, "Endpoint mapper answer: 1 tower(s)"), nullptr);
    EXPECT_NE(find(flow.details(25).fields, "SRVSVC (Server Service) v3.0: ncacn_ip_tcp 10.0.0.2:49667"), nullptr);
    EXPECT_TRUE(has(k[25].info, "DCERPC Response (CallID: 2), EPM (Endpoint Mapper)")) << k[25].info;
    ASSERT_NE(flow.processor().sessions().dceRpcEndpoint("10.0.0.2", 49667, false, 26), nullptr);
    EXPECT_EQ(flow.processor().sessions().dceRpcEndpoint("10.0.0.2", 49667, false, 25), nullptr);
    EXPECT_EQ(k[34].protocol, "DCERPC") << "a TCP connection to the mapped port";
    EXPECT_EQ(k[34].info, "Request (CallID: 2), Opnum: 15");
    EXPECT_EQ(k[35].protocol, "DCERPC");
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, TheSameBytesWrittenToAFileOfADiskShareAreNotAPdu) {
    Flow flow(50000, 445, "dce_pipe_disk");
    addScenario(flow);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_FALSE(has(k[30].info, "DCERPC")) << k[30].info;
    EXPECT_FALSE(matches("dcerpc", k[30]));
    EXPECT_EQ(find(flow.details(30).fields, "DCE/RPC"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, BytesWrittenToAPipeThatAreNoPduAreLabelled) {
    Flow flow(50000, 445, "dce_pipe_junk");
    addScenario(flow);
    flow.load();
    EXPECT_FALSE(has(flow.packets()[32].info, "DCERPC")) << flow.packets()[32].info;
    EXPECT_NE(find(flow.details(32).fields, "[Named pipe data (10 bytes): not a DCE/RPC PDU]"), nullptr);
    EXPECT_FALSE(matches("dcerpc", flow.packets()[32]));
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, WithoutTheOpeningOfThePipeNothingIsDecoded) {
    // the capture starts after the Create: the FileId is unknown, so the transfer is no known pipe's
    Flow flow(50000, 445, "dce_pipe_midstream");
    flow.client(kWriteBind).server(kWriteBindResp).client(kCallReq).server(kCallResp);
    flow.load();
    for (const auto &p: flow.packets()) EXPECT_FALSE(has(p.info, "DCERPC")) << p.info;
    flow.expectReplayEqualsLoad();
}

TEST(DceRpcPipe, ThePipeSurvivesDamagedCapturesAndReplayStaysEqual) {
    std::mt19937 rng(0x9e37);
    for (int round = 0; round < 80; ++round) {
        Flow flow(50000, 445, "dce_pipe_damage" + std::to_string(round));
        for (const Msg &m: kScenario) {
            std::string d = *m.data;
            if (rng() % 4 == 0) {
                const int kind = static_cast<int>(rng() % 3);
                if (kind == 0 && d.size() > 8) d.resize(8 + rng() % (d.size() - 8));
                else for (int k = 0; k < 1 + static_cast<int>(rng() % 4); ++k) d[rng() % d.size()] = static_cast<char>(rng());
            }
            if (m.client) flow.client(d); else flow.server(d);
        }
        flow.load();
        flow.expectReplayEqualsLoad();
    }
}

TEST(DceRpcPipe, TheBudgetRunningOutIsSaidInTheTree) {
    Flow flow(50000, 445, "dce_pipe_budget");
    flow.processor().sessions().setMaxMemoryPerTable(4000);
    addScenario(flow);
    flow.load();
    EXPECT_TRUE(flow.processor().sessions().hasStateLost());
    flow.expectReplayEqualsLoad();
}

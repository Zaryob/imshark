// SMB2 / SMB3 ([MS-SMB2]): messages packed with Python's struct module from the layouts of the specification - the 64 byte header
// (ProtocolId, StructureSize 64, CreditCharge, Status, Command, Credits, Flags, NextCommand, MessageId, Reserved|TreeId or
// AsyncId, SessionId, Signature), Negotiate (StructureSize 36 / 65), Session Setup (25 / 9) with NTLMSSP messages, Tree Connect (9),
// Create (57), Read / Write (49), the Transform header ([MS-SMB2] 2.2.41) and NetBIOS session service messages. Python's encoder is
// the oracle; NT status values are the documented ones ([MS-ERREF]: 0xC0000016 STATUS_MORE_PROCESSING_REQUIRED, 0x103 STATUS_PENDING,
// 0xC0000101 STATUS_DIRECTORY_NOT_EMPTY, 0xC0000103 STATUS_NOT_A_DIRECTORY, 0xC0000133 STATUS_TIME_DIFFERENCE_AT_DC).
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/smb2.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kNegReq = bytes("0000006efe534d42400000000000000000000100000000000000000001000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000024000500010000007f000000000102030405060708090a0b0c0d0e0f"
        "000000000000000002021002000302031103");
    const std::string kNegResp = bytes("00000081fe534d42400000000000000000000100010000000000000001000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000004100010011030000000102030405060708090a0b0c0d0e0f7f000000"
        "0000800000008000000080000000000000000000000000000000000080000000"
        "0000000000");
    const std::string kSsReq1 = bytes("00000078fe534d42400000000000000001000100000000000000000002000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000001900000100000000000000005800200000000000000000004e544c4d"
        "53535000010000001582086000000000000000000000000000000000");
    const std::string kSsResp1 = bytes("00000078fe534d4240000000160000c001000100010000000000000002000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "0000000009000000480030004e544c4d53535000020000000000000038000000"
        "158289e2efcdab896745230100000000000000000000000000000000");
    const std::string kSsReq2 = bytes("000000b2fe534d42400000000000000001000100000000000000000003000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "0000000019000001000000000000000058005a0000000000000000004e544c4d"
        "5353500003000000000000004000000000000000400000000800080040000000"
        "0a000a0048000000080008005200000000000000400000001582086043004f00"
        "5200500061006c006900630065005000430030003100");
    const std::string kSsResp2 = bytes("00000049fe534d42400000000000000001000100010000000000000003000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "00000000090000004800000000");
    const std::string kTcReq = bytes("00000062fe534d42400000000000000003000100000000000000000004000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "000000000900000048001a005c005c00660069006c00650073005c0073006800"
        "610072006500");
    const std::string kTcResp = bytes("00000050fe534d42400000000000000003000100010000000000000004000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000100001003000000002000000ff011f00");
    const std::string kCreateReq = bytes("00000096fe534d42400000000000000005000100000000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078001e00000000000000000064006f00"
        "630073005c007200650070006f00720074002e00740078007400");
    const std::string kReadReq = bytes("00000071fe534d42400000000000000008000100000000000000000006000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000031000000000001000010000000000000000102030405060708090a0b"
        "0c0d0e0f0000000000000000000000000000000000");
    const std::string kWriteReq = bytes("00000075fe534d42400000000000000009000100000000000000000007000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000031007000050000000000000000000000000102030405060708090a0b"
        "0c0d0e0f0000000000000000000000000000000068656c6c6f");
    const std::string kPending = bytes("00000049fe534d42400000000301000008000100030000000000000006000000"
        "0000000088776655443322110100100000000000000000000000000000000000"
        "00000000090000000000000000");
    const std::string kLogonFailure = bytes("00000049fe534d42400000006d0000c001000100010000000000000003000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000090000000000000000");
    const std::string kCompound = bytes("0000008cfe534d42400000000000000004000100040000004800000008000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000000400000000000000fe534d4240000000000000000200010004000000"
        "0000000009000000000000000000000000000000010010000000000000000000"
        "00000000000000000000000004000000");
    const std::string kTransform = bytes("00000160fd534d42000000000000000000000000000000000102030405060708"
        "090a0b0c0d0e0f102c0100000000010001001000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000");
    const std::string kNbssRequest = bytes("8100004400000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000");
    const std::string kNbssKeepalive = bytes("85000000");
    const std::string kSmb1 = bytes("00000024ff534d42720000000000000000000000000000000000000000000000"
        "0000000000000000");

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

    packet::PacketInfo one(const std::string &payload, bool fromClient = true, uint16_t port = 445) {
        Flow flow(50000, port, "smb2_one");
        if (fromClient) flow.client(payload); else flow.server(payload);
        flow.load();
        return flow.packets().at(0);
    }
}

TEST(Smb2, NegotiateListsTheDialectsAndTheResponseNamesTheChosenOne) {
    const auto req = one(kNegReq);
    EXPECT_EQ(req.protocol, "SMB2");
    EXPECT_EQ(req.info, "Negotiate Request [SMB 2.0.2, SMB 2.1, SMB 3.0, SMB 3.0.2, SMB 3.1.1]");
    EXPECT_TRUE(matches("smb2 && smb2.cmd == 0 && !smb2.flags.response", req));
    const auto resp = one(kNegResp, false);
    EXPECT_EQ(resp.info, "Negotiate Response, STATUS_SUCCESS [SMB 3.1.1]");
    EXPECT_TRUE(matches("smb2.dialect == 0x0311 && smb2.nt_status == 0 && smb2.flags.response", resp));
    EXPECT_FALSE(matches("smb2.dialect == 0x0311", req));
}

TEST(Smb2, SessionSetupRoundNamesTheNtlmsspMessagesAndTheUser) {
    Flow flow(50000, 445, "smb2_session");
    flow.client(kSsReq1).server(kSsResp1).client(kSsReq2).server(kSsResp2).server(kLogonFailure);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Session Setup Request [NTLMSSP_NEGOTIATE]");
    EXPECT_EQ(k[1].info, "Session Setup Response, STATUS_MORE_PROCESSING_REQUIRED [NTLMSSP_CHALLENGE]") << "every NTLM round trip";
    EXPECT_EQ(k[2].info, "Session Setup Request [NTLMSSP_AUTH] user=CORP\\alice");
    EXPECT_TRUE(matches("smb2.user == \"CORP\\\\alice\"", k[2]));
    EXPECT_EQ(k[3].info, "Session Setup Response, STATUS_SUCCESS");
    EXPECT_EQ(k[4].info, "Session Setup Response, STATUS_LOGON_FAILURE");
    EXPECT_TRUE(matches("smb2.nt_status == 0xC000006D", k[4]));
    EXPECT_NE(find(flow.details(2).fields, "NTLMSSP User: CORP\\alice"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Smb2, TreeConnectCreateReadAndWrite) {
    Flow flow(50000, 445, "smb2_files");
    flow.client(kTcReq).server(kTcResp).client(kCreateReq).client(kReadReq).client(kWriteReq);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Tree Connect Request, Path: \\\\files\\share");
    EXPECT_TRUE(matches("smb2.tree == \"\\\\\\\\files\\\\share\"", k[0]));
    EXPECT_EQ(k[1].info, "Tree Connect Response, STATUS_SUCCESS, TreeID: 0x0005");
    EXPECT_EQ(k[2].info, "Create Request, File: docs\\report.txt, TreeID: 0x0005");
    EXPECT_TRUE(matches("smb2.filename == \"docs\\\\report.txt\" && smb2.cmd == 5", k[2]));
    EXPECT_EQ(k[3].info, "Read Request, Len: 65536, Off: 4096, TreeID: 0x0005");
    EXPECT_EQ(k[4].info, "Write Request, Len: 5, Off: 0, TreeID: 0x0005");
    EXPECT_NE(find(flow.details(2).fields, "File Name: docs\\report.txt"), nullptr);
    EXPECT_NE(find(flow.details(0).fields, "Path: \\\\files\\share"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Smb2, AsyncResponsesCompoundsAndTheLegacyProtocol) {
    const auto pending = one(kPending, false);
    EXPECT_EQ(pending.info, "Read Response, STATUS_PENDING") << "STATUS_PENDING, not STATUS_NOT_A_DIRECTORY; and no tree id from the AsyncId";
    EXPECT_TRUE(matches("smb2.nt_status == 0x103", pending));
    const auto compound = one(kCompound);
    EXPECT_EQ(compound.info, "Tree Disconnect Request, TreeID: 0x0005, Logoff Request") << "NextCommand is followed";
    EXPECT_EQ(compound.app_type, 4u);
    const auto smb1 = one(kSmb1);
    EXPECT_EQ(smb1.protocol, "SMB");
}

TEST(Smb2, StatusNamesFollowMsErref) {
    const std::pair<uint32_t, const char *> cases[] = {
        {0x00000103, "STATUS_PENDING"}, {0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY"}, {0xC0000103, "STATUS_NOT_A_DIRECTORY"},
        {0xC0000133, "STATUS_TIME_DIFFERENCE_AT_DC"}, {0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED"}, {0x80000006, "STATUS_NO_MORE_FILES"},
        {0xC0000022, "STATUS_ACCESS_DENIED"}, {0xC00000CC, "STATUS_BAD_NETWORK_NAME"}};
    for (const auto &c: cases) {
        std::string pkt = kLogonFailure;
        for (int i = 0; i < 4; ++i) pkt[4 + 8 + i] = static_cast<char>((c.first >> (8 * i)) & 0xff);
        EXPECT_EQ(one(pkt, false).info, std::string("Session Setup Response, ") + c.second);
    }
    std::string unknown = kLogonFailure;
    unknown[4 + 8] = 0x44; unknown[4 + 9] = 0x33; unknown[4 + 10] = 0x22; unknown[4 + 11] = 0x11;
    EXPECT_EQ(one(unknown, false).info, "Session Setup Response, NT_STATUS_0x11223344");
}

TEST(Smb2, EncryptedMessagesAreLabelledNotSilentlyDropped) {
    const auto p = one(kTransform);
    EXPECT_EQ(p.protocol, "SMB2");
    EXPECT_EQ(p.info, "Encrypted SMB3 (352 bytes), Session: 0x0000000000100001");
    EXPECT_TRUE(matches("smb2.encrypted", p));
    EXPECT_FALSE(matches("smb2.cmd == 0", p));
}

TEST(Smb2, NetbiosSessionServiceMessagesOnPort139) {
    Flow flow(50000, 139, "smb2_nbss");
    flow.client(kNbssRequest).server(bytes("82000000")).client(kNbssKeepalive).client(kNegReq);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "NBSS");
    EXPECT_EQ(k[0].info, "NBSS Session Request");
    EXPECT_EQ(k[1].info, "NBSS Positive Session Response");
    EXPECT_EQ(k[2].info, "NBSS Session Keep Alive");
    EXPECT_EQ(k[3].protocol, "SMB2");
    flow.expectReplayEqualsLoad();
}

TEST(Smb2, MessagesSplitOverSegmentsAreReassembled) {
    Flow flow(50000, 445, "smb2_split");
    flow.client(kCreateReq.substr(0, 30)).client(kCreateReq.substr(30, 60)).client(kCreateReq.substr(90));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_EQ(k[2].info.rfind("Create Request, File: docs\\report.txt", 0), 0u) << k[2].info;
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Framer, FramesByTheSessionHeaderAndRejectsOtherBytes) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameSmb2(s.data(), s.size()); };
    EXPECT_EQ(frame(kNegReq.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(kNegReq.substr(0, 40)).kind, K::NeedMore);
    EXPECT_EQ(frame(kNegReq.substr(0, 40)).length, kNegReq.size());
    EXPECT_EQ(frame(kNegReq).kind, K::Complete);
    EXPECT_EQ(frame(kNegReq + kNegReq).length, kNegReq.size());
    EXPECT_EQ(frame(kNbssKeepalive).length, 4u);
    EXPECT_EQ(frame(kTransform).kind, K::Complete);
    EXPECT_EQ(frame(bytes("1603010004" "01000000")).kind, K::Reject) << "a TLS record";
    EXPECT_EQ(frame(bytes("00000010" "0102030405060708")).kind, K::Reject) << "a session message that is no SMB";
    EXPECT_EQ(frame(bytes("00ffffff" "fe534d42")).kind, K::Reject) << "16 MB is more than the stream table buffers";
    EXPECT_EQ(frame(bytes("42")).kind, K::Reject);
}

TEST(Smb2, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kNegReq, &kNegResp, &kSsReq1, &kSsResp1, &kSsReq2, &kSsResp2, &kTcReq, &kTcResp, &kCreateReq, &kReadReq, &kWriteReq,
                                &kPending, &kLogonFailure, &kCompound, &kTransform, &kNbssRequest, &kSmb1}) {
        appflow::sweepPayload(*m, 445, 0x534d);
        appflow::sweepPayload(*m, 139, 0x534e);
    }
}

TEST(Smb2, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"SMB2", "SMB", "NBSS"});
}

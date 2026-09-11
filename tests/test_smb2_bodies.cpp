// SMB2 command bodies ([MS-SMB2] 2.2.x): Close, Flush, Create (response and create contexts), Read / Write responses, IOCTL, Query
// Directory, Change Notify, Query Info / Set Info with the common [MS-FSCC] information classes, the Error response, the credit
// fields and the 3.1.1 negotiate contexts. Oracle: an independent Python (struct) encoder of the specification layouts
// (scratchpad smbvec.py, the hex below is its output); FSCTL codes are recomputed with winioctl.h's CTL_CODE formula
// ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method) and FILETIME strings with Python's datetime.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
const std::string kCloseReq = bytes("00000058fe534d42400001000000000006000100000000000000000006000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000180001000000000011000000000000002200000000000000");
const std::string kCloseResp = bytes("0000007cfe534d42400001000000000006000100010000000000000006000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000003c0001000000000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000");
const std::string kCreateResp = bytes("00000099fe534d42400001000000000005000100010000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "0000000011000000000000002200000000000000000000000000000000");
const std::string kCreateWithContexts = bytes("000000d8fe534d42400001000000000005000100000000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078001e00980000004000000064006f00"
        "630073005c007200650070006f00720074002e00740078007400000018000000"
        "1000040000001800000000004d78416300000000000000001000040000001800"
        "1000000044486e510000000000000000000000000000000000000000");
const std::string kIoctlPipe = bytes("00000088fe534d4240000100000000000b000100000000000000000009000000"
        "0000000000000000070000000100100000000000000000000000000000000000"
        "000000003900000017c011001100000000000000220000000000000078000000"
        "1000000000000000000000000000000000100000010000000000000005000b03"
        "000000000000000000000000");
const std::string kIoctlPipeResp = bytes("00000088fe534d4240000100000000000b000100010000000000000009000000"
        "0000000000000000070000000100100000000000000000000000000000000000"
        "000000003100000017c011001100000000000000220000000000000000000000"
        "000000007000000018000000000000000000000005000c030000000000000000"
        "000000000000000000000000");
const std::string kIoctlValidate = bytes("00000090fe534d4240000100000000000b00010000000000000000000a000000"
        "0000000000000000070000000100100000000000000000000000000000000000"
        "000000003900000004021400ffffffffffffffffffffffffffffffff78000000"
        "1800000000000000000000000000000000100000010000000000000000000000"
        "0000000000000000000000000000000000000000");
const std::string kQueryInfoStdReq = bytes("00000069fe534d4240000100000000001000010000000000000000000b000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000029000105001000000000000000000000000000000000000011000000"
        "00000000220000000000000000");
const std::string kQueryInfoStdResp = bytes("00000060fe534d4240000100000000001000010001000000000000000b000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000009004800180000000020000000000000d20400000000000001000000"
        "00000000");
const std::string kQueryInfoBasicResp = bytes("00000070fe534d4240000100000000001000010001000000000000000c000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000090048002800000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda012000000000000000");
const std::string kQueryFsSizeReq = bytes("00000069fe534d4240000100000000001000010000000000000000000d000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000029000203001000000000000000000000000000000000000011000000"
        "00000000220000000000000000");
const std::string kQueryFsSizeResp = bytes("00000060fe534d4240000100000000001000010001000000000000000d000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000090048001800000040420f000000000090d003000000000008000000"
        "00020000");
const std::string kQuerySecurityReq = bytes("00000069fe534d4240000100000000001000010000000000000000000e000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000029000300001000000000000000000000070000000000000011000000"
        "00000000220000000000000000");
const std::string kSetEofReq = bytes("00000068fe534d4240000100000000001100010000000000000000000f000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000021000114080000006000000000000000110000000000000022000000"
        "000000008813000000000000");
const std::string kSetDeleteReq = bytes("00000061fe534d42400001000000000011000100000000000000000010000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000002100010d010000006000000000000000110000000000000022000000"
        "0000000001");
const std::string kSetRenameReq = bytes("0000008cfe534d42400001000000000011000100000000000000000011000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000002100010a2c0000006000000000000000110000000000000022000000"
        "0000000001000000000000000000000000000000180000006e00650077002000"
        "6e0061006d0065002e00740078007400");
const std::string kQueryDirReq = bytes("0000006afe534d4240000100000000000e000100000000000000000012000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000021002501000000001100000000000000220000000000000060000a00"
        "000001002a002e00740078007400");
const std::string kQueryDirResp = bytes("00000070fe534d4240000100000000000e000100010000000000000012000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000009004800280000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000");
const std::string kReadResp = bytes("0000005bfe534d42400001000000000008000100010000000000000013000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000110050000b000000000000000000000068656c6c6f20776f726c64");
const std::string kWriteResp = bytes("00000050fe534d42400001000000000009000100010000000000000014000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000110000000b0000000000000000000000");
const std::string kFlushReq = bytes("00000058fe534d42400001000000000007000100000000000000000015000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000180000000000000011000000000000002200000000000000");
const std::string kErrorResp = bytes("00000049fe534d4240000100340000c005000100010000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000090000000000000000");
const std::string kNotifyReq = bytes("00000060fe534d4240000100000000000f000100000000000000000016000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000020000100000001001100000000000000220000000000000017000000"
        "00000000");
const std::string kNegotiate311 = bytes("000000befe534d42400000000000000000001f00000000000000000000000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "0000000024000300010000007f000000000102030405060708090a0b0c0d0e0f"
        "7000000003000000020202031103000000000000010026000000000001002000"
        "0100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaa000002000600000000000200020001000000080006000000000002000100"
        "0200");
    // clang-format on

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }

    // the packet's info, and the detail tree (Replay) of a single message from the client or the server
    struct Decoded {
        packet::PacketInfo load, detail;
    };
    Decoded decode(const std::string &payload, bool fromClient = true) {
        Flow flow(50000, 445, "smb2_body");
        if (fromClient) flow.client(payload); else flow.server(payload);
        flow.load();
        Decoded d;
        d.load = flow.packets().at(0);
        d.detail = flow.details(0);
        flow.expectReplayEqualsLoad();
        return d;
    }
    ::testing::AssertionResult hasField(const Decoded &d, const std::string &prefix) {
        if (find(d.detail.fields, prefix)) return ::testing::AssertionSuccess();
        return ::testing::AssertionFailure() << "no field starting with '" << prefix << "'";
    }
}

TEST(Smb2Bodies, CloseCarriesTheFileIdAndTheResponseTheFinalAttributes) {
    const auto req = decode(kCloseReq);
    EXPECT_EQ(req.load.info, "Close Request, TreeID: 0x0005");
    EXPECT_TRUE(hasField(req, "File ID: persistent 0x0000000000000011, volatile 0x0000000000000022"));
    EXPECT_TRUE(hasField(req, "Flags: 0x0001 (POSTQUERY_ATTRIB)"));
    const auto resp = decode(kCloseResp, false);
    EXPECT_EQ(resp.load.info, "Close Response, STATUS_SUCCESS, TreeID: 0x0005");
    EXPECT_TRUE(hasField(resp, "Creation Time: 2024-03-05 14:30:15 UTC"));
    EXPECT_TRUE(hasField(resp, "Allocation Size: 4096"));
    EXPECT_TRUE(hasField(resp, "End Of File: 1234"));
    EXPECT_TRUE(hasField(resp, "File Attributes: 0x00000020 (ARCHIVE)"));
}

TEST(Smb2Bodies, CreateResponseShowsTheActionTheSizeAndTheFileId) {
    const auto resp = decode(kCreateResp, false);
    EXPECT_EQ(resp.load.info, "Create Response, STATUS_SUCCESS, Size: 1234, TreeID: 0x0005");
    EXPECT_TRUE(hasField(resp, "Create Action: FILE_OPENED (1)"));
    EXPECT_TRUE(hasField(resp, "File ID: persistent 0x0000000000000011, volatile 0x0000000000000022"));
    EXPECT_TRUE(hasField(resp, "End Of File: 1234"));
}

TEST(Smb2Bodies, CreateRequestNamesItsContextsAndTheDisposition) {
    const auto req = decode(kCreateWithContexts);
    EXPECT_EQ(req.load.info, "Create Request, File: docs\\report.txt [MxAc, DHnQ], TreeID: 0x0005");
    EXPECT_TRUE(hasField(req, "Context MxAc (query maximal access), data 0 bytes"));
    EXPECT_TRUE(hasField(req, "Context DHnQ (durable handle request), data 16 bytes"));
    EXPECT_TRUE(hasField(req, "Disposition: FILE_OPEN (1)"));
    EXPECT_TRUE(hasField(req, "File Name: docs\\report.txt"));
    EXPECT_EQ(req.load.app_text, "docs\\report.txt");
}

TEST(Smb2Bodies, IoctlNamesTheFunctionAndShowsTheSizes) {
    const auto req = decode(kIoctlPipe);
    EXPECT_EQ(req.load.info, "Ioctl Request, FSCTL_PIPE_TRANSCEIVE, In: 16, TreeID: 0x0007");
    EXPECT_TRUE(hasField(req, "Function: FSCTL_PIPE_TRANSCEIVE (0x0011c017)"));
    EXPECT_TRUE(hasField(req, "Flags: 0x00000001 (IS_FSCTL)"));
    EXPECT_TRUE(hasField(req, "File ID: persistent 0x0000000000000011"));
    const auto resp = decode(kIoctlPipeResp, false);
    EXPECT_EQ(resp.load.info, "Ioctl Response, STATUS_SUCCESS, FSCTL_PIPE_TRANSCEIVE, Out: 24, TreeID: 0x0007");
    const auto validate = decode(kIoctlValidate);
    EXPECT_EQ(validate.load.info, "Ioctl Request, FSCTL_VALIDATE_NEGOTIATE_INFO, In: 24, TreeID: 0x0007");
}

TEST(Smb2Bodies, EveryFsctlNameFollowsTheCtlCodeFormula) {
    struct C { uint32_t device, function, method, access; const char *name; };
    const C cases[] = {
        {0x11, 5, 3, 3, "FSCTL_PIPE_TRANSCEIVE"}, {0x11, 3, 0, 1, "FSCTL_PIPE_PEEK"}, {0x11, 6, 0, 0, "FSCTL_PIPE_WAIT"},
        {0x06, 101, 0, 0, "FSCTL_DFS_GET_REFERRALS"}, {0x06, 108, 0, 0, "FSCTL_DFS_GET_REFERRALS_EX"},
        {0x09, 41, 0, 0, "FSCTL_SET_REPARSE_POINT"}, {0x09, 42, 0, 0, "FSCTL_GET_REPARSE_POINT"}, {0x09, 49, 0, 0, "FSCTL_SET_SPARSE"},
        {0x09, 51, 3, 1, "FSCTL_QUERY_ALLOCATED_RANGES"}, {0x09, 50, 0, 2, "FSCTL_SET_ZERO_DATA"},
        {0x14, 117, 0, 0, "FSCTL_LMR_REQUEST_RESILIENCY"}, {0x14, 127, 0, 0, "FSCTL_QUERY_NETWORK_INTERFACE_INFO"},
        {0x14, 129, 0, 0, "FSCTL_VALIDATE_NEGOTIATE_INFO"}, {0x14, 30, 0, 0, "FSCTL_SRV_REQUEST_RESUME_KEY"},
        {0x14, 25, 0, 1, "FSCTL_SRV_ENUMERATE_SNAPSHOTS"}, {0x14, 60, 2, 1, "FSCTL_SRV_COPYCHUNK"}, {0x14, 60, 2, 2, "FSCTL_SRV_COPYCHUNK_WRITE"}};
    for (const C &c: cases) {
        const uint32_t code = (c.device << 16) | (c.access << 14) | (c.function << 2) | c.method;
        std::string pkt = kIoctlPipe;
        for (int i = 0; i < 4; ++i) pkt[4 + 64 + 4 + i] = static_cast<char>((code >> (8 * i)) & 0xff);
        EXPECT_NE(decode(pkt).load.info.find(std::string(", ") + c.name + ", "), std::string::npos) << c.name << " " << std::hex << code;
    }
    std::string unknown = kIoctlPipe;
    unknown[4 + 64 + 4] = 0x01; unknown[4 + 64 + 5] = 0; unknown[4 + 64 + 6] = 0; unknown[4 + 64 + 7] = 0;
    EXPECT_NE(decode(unknown).load.info.find(", 0x00000001, "), std::string::npos);
}

TEST(Smb2Bodies, QueryAndSetInfoNameTheClass) {
    EXPECT_EQ(decode(kQueryInfoStdReq).load.info, "Query Info Request, FileStandardInformation, TreeID: 0x0005");
    const auto fs = decode(kQueryFsSizeReq);
    EXPECT_EQ(fs.load.info, "Query Info Request, FileFsSizeInformation, TreeID: 0x0005");
    EXPECT_TRUE(hasField(fs, "Info Type: File System (2)"));
    EXPECT_TRUE(hasField(fs, "Info Class: FileFsSizeInformation (3)"));
    const auto sec = decode(kQuerySecurityReq);
    EXPECT_EQ(sec.load.info, "Query Info Request, Security info, TreeID: 0x0005");
    EXPECT_TRUE(hasField(sec, "Additional Information: 0x00000007 (OWNER, GROUP, DACL)"));
    EXPECT_EQ(decode(kSetEofReq).load.info, "Set Info Request, FileEndOfFileInformation, Size: 5000, TreeID: 0x0005");
    EXPECT_EQ(decode(kSetDeleteReq).load.info, "Set Info Request, FileDispositionInformation, Delete, TreeID: 0x0005");
    const auto rename = decode(kSetRenameReq);
    EXPECT_EQ(rename.load.info, "Set Info Request, FileRenameInformation, TreeID: 0x0005");
    EXPECT_TRUE(hasField(rename, "Replace If Exists: yes"));
    EXPECT_TRUE(hasField(rename, "File Name: new name.txt"));
    EXPECT_TRUE(hasField(decode(kSetEofReq), "End Of File: 5000"));
    EXPECT_TRUE(hasField(decode(kSetDeleteReq), "Delete Pending: yes"));
}

TEST(Smb2Bodies, QueryInfoResponseAloneOnlyShowsItsLength) {
    // without its request the information class is unknown: the buffer is not interpreted
    EXPECT_EQ(decode(kQueryInfoStdResp, false).load.info, "Query Info Response, STATUS_SUCCESS, Len: 24, TreeID: 0x0005");
}

TEST(Smb2Bodies, QueryDirectoryReadWriteFlushAndNotify) {
    const auto qd = decode(kQueryDirReq);
    EXPECT_EQ(qd.load.info, "Query Directory Request, Pattern: *.txt, FileIdBothDirectoryInformation, TreeID: 0x0005");
    EXPECT_TRUE(hasField(qd, "Search Pattern: *.txt"));
    EXPECT_TRUE(hasField(qd, "Flags: 0x01 (RESTART_SCANS)"));
    EXPECT_EQ(decode(kQueryDirResp, false).load.info, "Query Directory Response, STATUS_SUCCESS, Len: 40, TreeID: 0x0005");
    const auto rd = decode(kReadResp, false);
    EXPECT_EQ(rd.load.info, "Read Response, STATUS_SUCCESS, Len: 11, TreeID: 0x0005");
    EXPECT_TRUE(hasField(rd, "Data Offset: 80"));
    EXPECT_EQ(decode(kWriteResp, false).load.info, "Write Response, STATUS_SUCCESS, Len: 11, TreeID: 0x0005");
    EXPECT_EQ(decode(kFlushReq).load.info, "Flush Request, TreeID: 0x0005");
    EXPECT_TRUE(hasField(decode(kFlushReq), "File ID: persistent 0x0000000000000011"));
    const auto n = decode(kNotifyReq);
    EXPECT_EQ(n.load.info, "Change Notify Request, Watch tree, TreeID: 0x0005");
    EXPECT_TRUE(hasField(n, "Completion Filter: 0x00000017"));
}

TEST(Smb2Bodies, AnErrorResponseHasTheErrorBodyNotTheCommandBody) {
    const auto e = decode(kErrorResp, false);
    EXPECT_EQ(e.load.info, "Create Response, STATUS_OBJECT_NAME_NOT_FOUND, TreeID: 0x0005");
    EXPECT_TRUE(hasField(e, "Error Context Count: 0"));
    EXPECT_TRUE(hasField(e, "Byte Count: 0"));
    EXPECT_FALSE(find(e.detail.fields, "Create Action"));
    EXPECT_FALSE(find(e.detail.fields, "File ID"));
}

TEST(Smb2Bodies, TheHeaderShowsCreditsAndTheNegotiate311ContextsAreListed) {
    const auto n = decode(kNegotiate311);
    EXPECT_EQ(n.load.info, "Negotiate Request [SMB 2.0.2, SMB 3.0.2, SMB 3.1.1]");
    EXPECT_TRUE(hasField(n, "Credit Charge: 0"));
    EXPECT_TRUE(hasField(n, "Credits requested: 31"));
    EXPECT_TRUE(hasField(n, "Security Mode: 0x0001 (signing enabled)"));
    EXPECT_TRUE(hasField(n, "Negotiate Contexts (3)"));
    EXPECT_TRUE(hasField(n, "SMB2_PREAUTH_INTEGRITY_CAPABILITIES (1, 38 bytes)"));
    EXPECT_TRUE(hasField(n, "Hash algorithms: 1 (SHA-512)"));
    EXPECT_TRUE(hasField(n, "SMB2_ENCRYPTION_CAPABILITIES (2, 6 bytes)"));
    EXPECT_TRUE(hasField(n, "Ciphers (2): AES-128-GCM, AES-128-CCM"));
    EXPECT_TRUE(hasField(n, "SMB2_SIGNING_CAPABILITIES (8, 6 bytes)"));
    EXPECT_TRUE(hasField(n, "Signing algorithms (2): AES-CMAC, AES-GMAC"));
}

TEST(Smb2Bodies, FileTimesAreConvertedFromFiletime) {
    struct T { uint64_t ft; const char *text; };
    const T cases[] = {
        {0x0000000000989680, "1601-01-01 00:00:01 UTC"},
        {0x019db1ded53e8000, "1970-01-01 00:00:00 UTC"},
        {0x01bf8311159da980, "2000-02-29 23:59:59 UTC"},
        {0x01e9fd1ed53e8000, "2038-01-19 03:14:08 UTC"},
        {0x022f9fc03dc34000, "2100-03-01 00:00:00 UTC"},
        {0x01db5be01921a980, "2024-12-31 23:59:59 UTC"},
        {0x24c85a5ed127a980, "9999-12-31 23:59:59 UTC"},
    };
    for (const T &t: cases) {
        std::string pkt = kCloseResp;
        for (int i = 0; i < 8; ++i) pkt[4 + 64 + 8 + i] = static_cast<char>((t.ft >> (8 * i)) & 0xff);
        EXPECT_TRUE(hasField(decode(pkt, false), std::string("Creation Time: ") + t.text)) << t.text;
    }
    std::string zero = kCloseResp;
    for (int i = 0; i < 8; ++i) zero[4 + 64 + 8 + i] = 0;
    EXPECT_TRUE(hasField(decode(zero, false), "Creation Time: not set"));
}

TEST(Smb2Bodies, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kCloseReq, &kCloseResp, &kCreateResp, &kCreateWithContexts, &kIoctlPipe, &kIoctlPipeResp, &kIoctlValidate, &kQueryInfoStdReq,
                                &kQueryInfoStdResp, &kQueryInfoBasicResp, &kQueryFsSizeReq, &kQueryFsSizeResp, &kQuerySecurityReq, &kSetEofReq, &kSetDeleteReq,
                                &kSetRenameReq, &kQueryDirReq, &kQueryDirResp, &kReadResp, &kWriteResp, &kFlushReq, &kErrorResp, &kNotifyReq, &kNegotiate311}) {
        appflow::sweepPayload(*m, 445, 0x5b0d);
    }
}

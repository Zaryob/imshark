// SMB2 trees, files and request/response matching as the dissector uses them: a 29 packet capture of one connection (tree
// connects, two creates answered in the opposite order, reads and writes with swapped replies, a query info answered with its
// information class, a related Create + Read + Close compound and its compound response, an asynchronous read with an interim
// STATUS_PENDING response, a close followed by a read of the closed file, a response nobody asked for, the IPC$ share with a named
// pipe, a tree disconnect and a read on the dead tree).
// Oracle: scratchpad scen.py builds the messages with Python's struct module and walks the same capture with an independent
// reference model (plain dictionaries: trees, files, pending requests by MessageId); kExpect below is the model's answer per packet
// (resolved file, share, frame of the matched request). The replay-equality check compares the load pass with the Replay of every
// packet, and `Smb2Tables.ReplayAfterTheCaptureIsLoadedAgrees...` uses a second, truncated copy of the capture.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/smb2_session.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
// packet: direction, file, share, request frame (0 = none) as the Python reference model computed them
struct Expect { bool client; const char *file; const char *share; int requestFrame; };
const Expect kExpect[] = {
    {true, "", "\\\\files\\share", 0},
    {false, "", "\\\\files\\share", 1},
    {true, "docs\\report.txt", "\\\\files\\share", 0},
    {true, "other.txt", "\\\\files\\share", 0},
    {false, "other.txt", "\\\\files\\share", 4},
    {false, "docs\\report.txt", "\\\\files\\share", 3},
    {true, "docs\\report.txt", "\\\\files\\share", 0},
    {true, "other.txt", "\\\\files\\share", 0},
    {false, "other.txt", "\\\\files\\share", 8},
    {false, "docs\\report.txt", "\\\\files\\share", 7},
    {true, "docs\\report.txt", "\\\\files\\share", 0},
    {false, "docs\\report.txt", "\\\\files\\share", 11},
    {true, "tmp.dat", "\\\\files\\share", 0},
    {false, "tmp.dat", "\\\\files\\share", 13},
    {true, "docs\\report.txt", "\\\\files\\share", 0},
    {false, "docs\\report.txt", "\\\\files\\share", 15},
    {false, "docs\\report.txt", "\\\\files\\share", 15},
    {true, "docs\\report.txt", "\\\\files\\share", 0},
    {false, "docs\\report.txt", "\\\\files\\share", 18},
    {true, "", "\\\\files\\share", 0},
    {false, "", "\\\\files\\share", 0},
    {true, "", "\\\\files\\IPC$", 0},
    {false, "", "\\\\files\\IPC$", 22},
    {true, "srvsvc", "\\\\files\\IPC$", 0},
    {false, "srvsvc", "\\\\files\\IPC$", 24},
    {true, "srvsvc", "\\\\files\\IPC$", 0},
    {true, "", "\\\\files\\share", 0},
    {false, "", "\\\\files\\share", 27},
    {true, "", "", 0},
};
const std::string kS01 = bytes("00000062fe534d42400001000000000003000100000000000000000004000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "000000000900000048001a005c005c00660069006c00650073005c0073006800"
        "610072006500");
const std::string kS02 = bytes("00000050fe534d42400001000000000003000100010000000000000004000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000100001000000000030000000ff011f00");
const std::string kS03 = bytes("00000096fe534d42400001000000000005000100000000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078001e00000000000000000064006f00"
        "630073005c007200650070006f00720074002e00740078007400");
const std::string kS04 = bytes("0000008afe534d42400001000000000005000100000000000000000006000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "800000000700000001000000400000007800120000000000000000006f007400"
        "6800650072002e00740078007400");
const std::string kS05 = bytes("00000099fe534d42400001000000000005000100010000000000000006000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "000000000b00000000000000b200000000000000000000000000000000");
const std::string kS06 = bytes("00000099fe534d42400001000000000005000100010000000000000005000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "000000000a00000000000000a200000000000000000000000000000000");
const std::string kS07 = bytes("00000071fe534d42400001000000000008000100000000000000000007000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000310000000010000000000000000000000a00000000000000a2000000"
        "000000000000000000000000000000000000000000");
const std::string kS08 = bytes("00000075fe534d42400001000000000009000100000000000000000008000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000310070000500000000000000000000000b00000000000000b2000000"
        "000000000000000000000000000000000000000068656c6c6f");
const std::string kS09 = bytes("00000050fe534d42400001000000000009000100010000000000000008000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000011000000050000000000000000000000");
const std::string kS10 = bytes("00000054fe534d42400001000000000008000100010000000000000007000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000001100500004000000000000000000000061626364");
const std::string kS11 = bytes("00000069fe534d42400001000000000010000100000000000000000009000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000002900010500100000000000000000000000000000000000000a000000"
        "00000000a20000000000000000");
const std::string kS12 = bytes("00000060fe534d42400001000000000010000100010000000000000009000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000009004800180000000020000000000000d20400000000000001000000"
        "00000000");
const std::string kS13 = bytes("00000158fe534d4240000100000000000500010000000000880000000a000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078000e00000000000000000074006d00"
        "70002e006400610074000000fe534d4240000100000000000800010004000000"
        "780000000b0000000000000000000000ffffffffffffffffffffffff00000000"
        "00000000000000000000000031000000001000000000000000000000ffffffff"
        "ffffffffffffffffffffffff0000000000000000000000000000000000000000"
        "00000000fe534d4240000100000000000600010004000000000000000c000000"
        "0000000000000000ffffffffffffffffffffffff000000000000000000000000"
        "000000001800000000000000ffffffffffffffffffffffffffffffff");
const std::string kS14 = bytes("00000174fe534d4240000100000000000500010001000000a00000000a000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "000000000c00000000000000c200000000000000000000000000000000000000"
        "00000000fe534d4240000100000000000800010005000000580000000b000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000001100500003000000000000000000000078797a0000000000fe534d42"
        "40000100000000000600010005000000000000000c0000000000000000000000"
        "050000000100100000000000000000000000000000000000000000003c000100"
        "0000000080758aa3096fda0180758aa3096fda0180758aa3096fda0180758aa3"
        "096fda010010000000000000d20400000000000020000000");
const std::string kS15 = bytes("00000071fe534d4240000100000000000800010000000000000000000d000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000310000000010000000000000000000000a00000000000000a2000000"
        "000000000000000000000000000000000000000000");
const std::string kS16 = bytes("00000049fe534d4240000100030100000800010003000000000000000d000000"
        "0000000088776655443322110100100000000000000000000000000000000000"
        "00000000090000000000000000");
const std::string kS17 = bytes("00000054fe534d4240000100000000000800010001000000000000000d000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000110050000400000000000000000000006c617465");
const std::string kS18 = bytes("00000058fe534d4240000100000000000600010000000000000000000e000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000018000100000000000a00000000000000a200000000000000");
const std::string kS19 = bytes("0000007cfe534d4240000100000000000600010001000000000000000e000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000003c0001000000000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000");
const std::string kS20 = bytes("00000071fe534d4240000100000000000800010000000000000000000f000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000310000000010000000000000000000000a00000000000000a2000000"
        "000000000000000000000000000000000000000000");
const std::string kS21 = bytes("0000007cfe534d42400001000000000006000100010000000000000063000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "000000003c0001000000000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000");
const std::string kS22 = bytes("00000060fe534d42400001000000000003000100000000000000000010000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "0000000009000000480018005c005c00660069006c00650073005c0049005000"
        "43002400");
const std::string kS23 = bytes("00000050fe534d42400001000000000003000100010000000000000010000000"
        "0000000000000000060000000100100000000000000000000000000000000000"
        "00000000100002000000000030000000ff011f00");
const std::string kS24 = bytes("00000084fe534d42400001000000000005000100000000000000000011000000"
        "0000000000000000060000000100100000000000000000000000000000000000"
        "0000000039000000020000000000000000000000000000000000000089001200"
        "8000000007000000010000004000000078000c00000000000000000073007200"
        "7600730076006300");
const std::string kS25 = bytes("00000099fe534d42400001000000000005000100010000000000000011000000"
        "0000000000000000060000000100100000000000000000000000000000000000"
        "00000000590000000100000080758aa3096fda0180758aa3096fda0180758aa3"
        "096fda0180758aa3096fda010010000000000000d20400000000000020000000"
        "000000000d00000000000000d200000000000000000000000000000000");
const std::string kS26 = bytes("00000074fe534d42400001000000000009000100000000000000000012000000"
        "0000000000000000060000000100100000000000000000000000000000000000"
        "00000000310070000400000000000000000000000d00000000000000d2000000"
        "000000000000000000000000000000000000000005000b03");
const std::string kS27 = bytes("00000044fe534d42400001000000000004000100000000000000000013000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000004000000");
const std::string kS28 = bytes("00000044fe534d42400001000000000004000100010000000000000013000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "0000000004000000");
const std::string kS29 = bytes("00000071fe534d42400001000000000008000100000000000000000014000000"
        "0000000000000000050000000100100000000000000000000000000000000000"
        "00000000310000000010000000000000000000000b00000000000000b2000000"
        "000000000000000000000000000000000000000000");
const std::string *const kScenario[] = {&kS01, &kS02, &kS03, &kS04, &kS05, &kS06, &kS07, &kS08, &kS09, &kS10, &kS11, &kS12, &kS13, &kS14, &kS15, &kS16, &kS17, &kS18, &kS19, &kS20, &kS21, &kS22, &kS23, &kS24, &kS25, &kS26, &kS27, &kS28, &kS29};
    // clang-format on

    constexpr size_t kPackets = sizeof(kExpect) / sizeof(kExpect[0]);

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }

    void addScenario(Flow &flow) {
        for (size_t i = 0; i < kPackets; ++i) {
            if (kExpect[i].client) flow.client(*kScenario[i]); else flow.server(*kScenario[i]);
        }
    }
}

TEST(Smb2Tables, EveryCommandResolvesItsShareFileAndRequestLikeTheReferenceModel) {
    static_assert(sizeof(kScenario) / sizeof(kScenario[0]) == kPackets);
    Flow flow(50000, 445, "smb2_tables");
    addScenario(flow);
    flow.load();
    ASSERT_EQ(flow.packets().size(), kPackets);
    for (size_t i = 0; i < kPackets; ++i) {
        const auto &p = flow.packets()[i];
        const auto d = flow.details(i);
        SCOPED_TRACE("packet " + std::to_string(i + 1) + ": " + p.info);
        EXPECT_EQ(p.protocol, "SMB2");
        EXPECT_EQ(p.app_text2, kExpect[i].file) << "the resolved file of the first command";
        EXPECT_EQ(d.app_text2, kExpect[i].file);
        const std::string file = kExpect[i].file, share = kExpect[i].share;
        // Info: the file, else the share, else the tree id; a Create request and a Tree Connect request name theirs themselves
        const bool request = kExpect[i].client;
        if (!file.empty() && !(request && p.app_type == 5)) EXPECT_NE(p.info.find(", File: " + file), std::string::npos);
        if (file.empty() && !share.empty() && !(request && p.app_type == 3)) EXPECT_NE(p.info.find(", Share: " + share), std::string::npos);
        if (file.empty() && share.empty()) EXPECT_EQ(p.info.find("Share: "), std::string::npos);
        // the tree
        const std::string reqText = "[Request in frame " + std::to_string(kExpect[i].requestFrame) + "]";
        if (kExpect[i].requestFrame) EXPECT_NE(find(d.fields, reqText), nullptr) << reqText;
        else EXPECT_EQ(find(d.fields, "[Request in frame"), nullptr);
        if (!share.empty()) EXPECT_NE(find(d.fields, "[Share: " + share + "]"), nullptr);
        if (!file.empty()) EXPECT_TRUE(find(d.fields, "[File: " + file + "]") || find(d.fields, "[Named pipe: " + file + "]"));
    }
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Tables, RequestsLearnWhereTheyWereAnswered) {
    Flow flow(50000, 445, "smb2_answered");
    addScenario(flow);
    flow.load();
    EXPECT_NE(find(flow.details(0).fields, "[Response in frame 2]"), nullptr);
    EXPECT_NE(find(flow.details(2).fields, "[Response in frame 6]"), nullptr) << "the create of docs\\report.txt was answered second";
    EXPECT_NE(find(flow.details(3).fields, "[Response in frame 5]"), nullptr);
    EXPECT_NE(find(flow.details(6).fields, "[Response in frame 10]"), nullptr) << "the read was answered after the write";
    EXPECT_NE(find(flow.details(14).fields, "[Response in frame 17]"), nullptr) << "the final response, not the interim one";
    EXPECT_NE(find(flow.details(15).fields, "[Interim response"), nullptr);
    EXPECT_NE(find(flow.details(15).fields, "[Request in frame 15]"), nullptr);
    EXPECT_EQ(find(flow.details(19).fields, "[Response in frame"), nullptr) << "the read of the closed file was never answered";
    EXPECT_NE(find(flow.details(20).fields, "[No request with this Message ID was seen]"), nullptr);
}

TEST(Smb2Tables, ACompoundOfRelatedOperationsUsesTheFileOfTheCreateInFrontOfIt) {
    Flow flow(50000, 445, "smb2_compound");
    addScenario(flow);
    flow.load();
    const auto &req = flow.packets()[12];
    EXPECT_EQ(req.info, "Create Request, File: tmp.dat, Share: \\\\files\\share, Read Request, Len: 4096, Off: 0, File: tmp.dat, Close Request, File: tmp.dat");
    EXPECT_NE(req.app_flags & 0x40, 0) << "compound";
    const auto d = flow.details(12);
    EXPECT_NE(find(d.fields, "[Related operation: the ids of the command before are used]"), nullptr);
    const auto &resp = flow.packets()[13];
    EXPECT_EQ(resp.info, "Create Response, STATUS_SUCCESS, Size: 1234, File: tmp.dat, Read Response, STATUS_SUCCESS, Len: 3, File: tmp.dat, Close Response, STATUS_SUCCESS, File: tmp.dat");
    // the Close in the compound closed the file the Create opened
    const std::string connection = dissect::smb2ConnectionKey("10.0.0.2", 445, "10.0.0.1", 50000);
    EXPECT_EQ(flow.processor().sessions().smb2OpenFile(connection, 0x0C, 0x0C2), nullptr);
    EXPECT_NE(flow.processor().sessions().smb2OpenFile(connection, 0x0D, 0x0D2), nullptr) << "the pipe was never closed";
}

TEST(Smb2Tables, QueryInfoResponseIsDecodedWithTheClassOfItsRequest) {
    Flow flow(50000, 445, "smb2_qinfo");
    addScenario(flow);
    flow.load();
    EXPECT_EQ(flow.packets()[10].info, "Query Info Request, FileStandardInformation, File: docs\\report.txt");
    EXPECT_EQ(flow.packets()[11].info, "Query Info Response, STATUS_SUCCESS, FileStandardInformation, File: docs\\report.txt");
    const auto d = flow.details(11);
    EXPECT_NE(find(d.fields, "File information: FileStandardInformation"), nullptr);
    EXPECT_NE(find(d.fields, "Allocation Size: 8192"), nullptr);
    EXPECT_NE(find(d.fields, "End Of File: 1234"), nullptr);
    EXPECT_NE(find(d.fields, "Number Of Links: 1"), nullptr);
    EXPECT_NE(find(d.fields, "Delete Pending: no"), nullptr);
    EXPECT_NE(find(d.fields, "Directory: no"), nullptr);
}

TEST(Smb2Tables, NamedPipesAreMarkedForTheProtocolsThatRideOnThem) {
    Flow flow(50000, 445, "smb2_pipes");
    addScenario(flow);
    flow.load();
    auto matches = [&](const std::string &expr, size_t i) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr;
        return f.ok && f.filter.matches(flow.packets()[i]);
    };
    for (size_t i = 0; i < kPackets; ++i) {
        const bool pipe = i >= 21 && i <= 25;   // the IPC$ tree connect (22) through the write on the pipe (26)
        EXPECT_EQ(matches("smb2.pipe", i), pipe) << "packet " << i + 1;
    }
    EXPECT_TRUE(matches("smb2.file == \"srvsvc\" && smb2.pipe", 25));
    EXPECT_TRUE(matches("smb2.file == \"docs\\\\report.txt\"", 6));
    EXPECT_FALSE(matches("smb2.file == \"docs\\\\report.txt\"", 19)) << "the file was closed before packet 20";
    EXPECT_NE(find(flow.details(25).fields, "[Named pipe: srvsvc]"), nullptr);
    const std::string connection = dissect::smb2ConnectionKey("10.0.0.2", 445, "10.0.0.1", 50000);
    const auto *file = flow.processor().sessions().smb2OpenFile(connection, 0x0D, 0x0D2);
    ASSERT_NE(file, nullptr);
    EXPECT_TRUE(file->pipe);
    EXPECT_EQ(file->name, "srvsvc");
    EXPECT_EQ(file->share, "\\\\files\\IPC$");
}

TEST(Smb2Tables, AnotherConnectionWithTheSameIdsDoesNotSeeTheFirstOnesFiles) {
    Flow flow(50000, 445, "smb2_two_conn");
    addScenario(flow);
    flow.load();
    // the same read of FileId A as packet 7, on another client port: nothing is known there
    Flow other(50001, 445, "smb2_other_conn");
    other.client(*kScenario[6]);
    other.load();
    EXPECT_EQ(other.packets()[0].app_text2, "");
    EXPECT_EQ(other.packets()[0].info, "Read Request, Len: 4096, Off: 0, TreeID: 0x0005");
}

TEST(Smb2Tables, WhenTheBudgetRunsOutTheCommandsSayNothingAndTheTreeSaysWhy) {
    Flow flow(50000, 445, "smb2_budget");
    flow.processor().sessions().setMaxMemoryPerTable(2000);
    addScenario(flow);
    flow.load();
    EXPECT_TRUE(flow.processor().sessions().isTableStateLost("smb2"));
    // packets whose note could not be stored fall back to the raw tree id and carry the explanation
    bool sawLost = false;
    for (size_t i = 0; i < kPackets; ++i) {
        if (flow.details(i).fields.empty()) continue;
        if (find(flow.details(i).fields, "[SMB2 session state lost")) sawLost = true;
    }
    EXPECT_TRUE(sawLost);
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Tables, TruncationAndMutationOfTheScenarioStayInsideTheFrame) {
    for (size_t i = 0; i < kPackets; i += 2) appflow::sweepPayload(*kScenario[i], 445, 0x7ab0 + static_cast<uint32_t>(i));
}

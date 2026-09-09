// The SMB2 session table (dissect/smb2_session.cpp): TreeId -> share, FileId -> file name, request <-> response matching by
// MessageId, related operations of compounds, ids reused after a close, connections told apart, the memory budget and the
// pending bound, the SessionTables glue (frozen, state lost). The expectations are written by hand from [MS-SMB2] 3.3.5 (what a
// server does with the ids), not computed by the code under test.
#include <gtest/gtest.h>

#include <string>

#include <dissect/session.h>

using dissect::Smb2Command;
using dissect::Smb2Note;

namespace {
    constexpr size_t kBig = 64u << 20;
    constexpr uint64_t kAll = ~0ull;
    const std::string kConn = dissect::smb2ConnectionKey("10.0.0.2", 445, "10.0.0.1", 50000);

    Smb2Command req(uint16_t command, uint64_t messageId, uint64_t session = 0x100001, uint32_t tree = 0) {
        Smb2Command c;
        c.command = command;
        c.messageId = messageId;
        c.sessionId = session;
        c.treeId = tree;
        return c;
    }
    Smb2Command resp(uint16_t command, uint64_t messageId, uint32_t status = 0, uint64_t session = 0x100001, uint32_t tree = 0) {
        Smb2Command c = req(command, messageId, session, tree);
        c.response = true;
        c.status = status;
        return c;
    }
    Smb2Command withFile(Smb2Command c, uint64_t p, uint64_t v) {
        c.hasFileId = true;
        c.filePersistent = p;
        c.fileVolatile = v;
        return c;
    }
    Smb2Command withName(Smb2Command c, const std::string &name) {
        c.name = name;
        return c;
    }

    struct Probe {
        dissect::Smb2Table t;
        uint32_t packet = 0;
        bool lost = false;
        const Smb2Note *go(const Smb2Command &c, uint8_t index = 0, const std::string &conn = kConn, int64_t seq = 0) {
            return t.observe(conn, ++packet, seq, index, c, kBig, lost);
        }
    };
}

TEST(Smb2Table, TreeConnectGivesTheTreeIdItsShareAndCreateGivesTheFileIdItsName) {
    Probe p;
    auto *tcReq = p.go(withName(req(dissect::kSmb2TreeConnect, 3), "\\\\files\\share"));
    EXPECT_EQ(tcReq->share, "\\\\files\\share");
    auto *tcResp = p.go(resp(dissect::kSmb2TreeConnect, 3, 0, 0x100001, 5));
    EXPECT_TRUE(tcResp->flags & Smb2Note::kMatched);
    EXPECT_EQ(tcResp->requestPacket, 1u);
    EXPECT_EQ(tcResp->share, "\\\\files\\share");
    EXPECT_EQ(tcReq->responsePacket, 2u) << "the request learns its response";
    EXPECT_TRUE(tcReq->flags & Smb2Note::kAnswered);
    ASSERT_NE(p.t.share(kConn, 0x100001, 5), nullptr);
    EXPECT_EQ(*p.t.share(kConn, 0x100001, 5), "\\\\files\\share");
    EXPECT_EQ(p.t.share(kConn, 0x100001, 6), nullptr);
    EXPECT_EQ(p.t.share(kConn, 0x100002, 5), nullptr) << "another session";

    auto *create = p.go(withName(req(dissect::kSmb2Create, 4, 0x100001, 5), "docs\\report.txt"));
    EXPECT_EQ(create->file, "docs\\report.txt");
    EXPECT_EQ(create->share, "\\\\files\\share");
    auto *created = p.go(withFile(resp(dissect::kSmb2Create, 4, 0, 0x100001, 5), 0x11, 0x22));
    EXPECT_EQ(created->file, "docs\\report.txt") << "the response shows the name of its request";
    ASSERT_NE(p.t.openFile(kConn, 0x11, 0x22), nullptr);
    EXPECT_EQ(p.t.openFile(kConn, 0x11, 0x22)->name, "docs\\report.txt");
    EXPECT_FALSE(p.t.openFile(kConn, 0x11, 0x22)->pipe);

    auto *read = p.go(withFile(req(8, 5, 0x100001, 5), 0x11, 0x22));
    EXPECT_EQ(read->file, "docs\\report.txt");
    EXPECT_EQ(read->share, "\\\\files\\share");
    auto *readResp = p.go(resp(8, 5, 0, 0x100001, 5));
    EXPECT_EQ(readResp->file, "docs\\report.txt") << "a response without FileId in its body gets the file of its request";

    p.go(withFile(req(dissect::kSmb2Close, 6, 0x100001, 5), 0x11, 0x22));
    EXPECT_NE(p.t.openFile(kConn, 0x11, 0x22), nullptr) << "open until the close is answered";
    p.go(resp(dissect::kSmb2Close, 6, 0, 0x100001, 5));
    EXPECT_EQ(p.t.openFile(kConn, 0x11, 0x22), nullptr);
    EXPECT_FALSE(p.lost);
}

TEST(Smb2Table, ResponsesAreMatchedByMessageIdInAnyOrder) {
    Probe p;
    p.go(withName(req(dissect::kSmb2Create, 10), "a"));            // packet 1
    p.go(withName(req(dissect::kSmb2Create, 11), "b"));            // packet 2
    p.go(withName(req(dissect::kSmb2Create, 12), "c"));            // packet 3
    auto *c = p.go(withFile(resp(dissect::kSmb2Create, 12), 3, 3)); // packet 4: the last request answered first
    auto *a = p.go(withFile(resp(dissect::kSmb2Create, 10), 1, 1)); // packet 5
    auto *b = p.go(withFile(resp(dissect::kSmb2Create, 11), 2, 2)); // packet 6
    EXPECT_EQ(c->requestPacket, 3u); EXPECT_EQ(c->file, "c");
    EXPECT_EQ(a->requestPacket, 1u); EXPECT_EQ(a->file, "a");
    EXPECT_EQ(b->requestPacket, 2u); EXPECT_EQ(b->file, "b");
    EXPECT_EQ(p.t.openFile(kConn, 1, 1)->name, "a");
    EXPECT_EQ(p.t.openFile(kConn, 2, 2)->name, "b");
    EXPECT_EQ(p.t.openFile(kConn, 3, 3)->name, "c");
    EXPECT_EQ(p.t.note(1, 0, 0)->responsePacket, 5u);
    EXPECT_EQ(p.t.note(3, 0, 0)->responsePacket, 4u);
    // a response nobody asked for, a response of another command with the same id, and a second response
    auto *none = p.go(resp(dissect::kSmb2Close, 99));
    EXPECT_TRUE(none->flags & Smb2Note::kUnmatched);
    p.go(req(8, 20));
    auto *wrong = p.go(resp(9, 20));
    EXPECT_TRUE(wrong->flags & Smb2Note::kUnmatched) << "the command has to agree";
    auto *twice = p.go(resp(dissect::kSmb2Create, 10));
    EXPECT_TRUE(twice->flags & Smb2Note::kUnmatched) << "a request is answered once";
}

TEST(Smb2Table, AnInterimStatusPendingResponseLeavesTheRequestWaiting) {
    Probe p;
    p.go(req(8, 7));
    auto *interim = p.go(resp(8, 7, dissect::kSmb2StatusPending));
    EXPECT_TRUE(interim->flags & Smb2Note::kInterim);
    EXPECT_TRUE(interim->flags & Smb2Note::kMatched);
    EXPECT_FALSE(p.t.note(1, 0, 0)->flags & Smb2Note::kAnswered);
    auto *final = p.go(resp(8, 7));
    EXPECT_TRUE(final->flags & Smb2Note::kMatched);
    EXPECT_FALSE(final->flags & Smb2Note::kInterim);
    EXPECT_EQ(p.t.note(1, 0, 0)->responsePacket, 3u);
}

TEST(Smb2Table, RelatedOperationsOfACompoundUseTheCommandBefore) {
    Probe p;
    p.go(withName(req(dissect::kSmb2TreeConnect, 1, 0x100001), "\\\\srv\\data"));
    p.go(resp(dissect::kSmb2TreeConnect, 1, 0, 0x100001, 9));
    // one message (packet 3, stream sequence 100): Create, Read (related), Close (related)
    auto *create = p.go(withName(req(dissect::kSmb2Create, 2, 0x100001, 9), "dir\\f.bin"), 0, kConn, 100);
    Smb2Command rd = withFile(req(8, 3, kAll, 0xFFFFFFFF), kAll, kAll); rd.related = true;
    Smb2Command cl = withFile(req(dissect::kSmb2Close, 4, kAll, 0xFFFFFFFF), kAll, kAll); cl.related = true;
    ++p.packet;   // the three commands share one packet
    auto *read = p.t.observe(kConn, p.packet, 100, 1, rd, kBig, p.lost);
    auto *close = p.t.observe(kConn, p.packet, 100, 2, cl, kBig, p.lost);
    EXPECT_EQ(create->file, "dir\\f.bin");
    EXPECT_EQ(read->file, "dir\\f.bin");
    EXPECT_EQ(read->share, "\\\\srv\\data") << "TreeId 0xFFFFFFFF: the tree of the command before";
    EXPECT_TRUE(read->flags & Smb2Note::kRelated);
    EXPECT_EQ(close->file, "dir\\f.bin");
    // the compound response: Create (FileId 5/6), Read, Close, all in one message
    ++p.packet;
    Smb2Command r0 = withFile(resp(dissect::kSmb2Create, 2, 0, 0x100001, 9), 5, 6);
    p.t.observe(kConn, p.packet, 7, 0, r0, kBig, p.lost);
    EXPECT_NE(p.t.openFile(kConn, 5, 6), nullptr);
    Smb2Command r1 = resp(8, 3, 0, 0x100001, 9);
    Smb2Command r2 = resp(dissect::kSmb2Close, 4, 0, 0x100001, 9);
    auto *readResp = p.t.observe(kConn, p.packet, 7, 1, r1, kBig, p.lost);
    p.t.observe(kConn, p.packet, 7, 2, r2, kBig, p.lost);
    EXPECT_EQ(readResp->file, "dir\\f.bin");
    EXPECT_EQ(p.t.openFile(kConn, 5, 6), nullptr) << "the related Close closed the file the Create response opened";
    EXPECT_FALSE(p.lost);
}

TEST(Smb2Table, AnIdIsReusedAfterTheCloseAndEarlierNotesKeepTheOldName) {
    Probe p;
    p.go(withName(req(dissect::kSmb2Create, 1), "first.txt"));
    p.go(withFile(resp(dissect::kSmb2Create, 1), 1, 1));
    auto *r1 = p.go(withFile(req(8, 2), 1, 1));
    p.go(withFile(req(dissect::kSmb2Close, 3), 1, 1));
    p.go(resp(dissect::kSmb2Close, 3));
    p.go(withName(req(dissect::kSmb2Create, 4), "second.txt"));
    p.go(withFile(resp(dissect::kSmb2Create, 4), 1, 1));
    auto *r2 = p.go(withFile(req(8, 5), 1, 1));
    EXPECT_EQ(r1->file, "first.txt");
    EXPECT_EQ(r2->file, "second.txt");
    EXPECT_EQ(p.t.note(3, 0, 0)->file, "first.txt") << "the stored note does not change when the id is reused";
}

TEST(Smb2Table, FailedAndForeignCommandsDoNotChangeTheTables) {
    Probe p;
    p.go(withName(req(dissect::kSmb2TreeConnect, 1), "\\\\srv\\x"));
    p.go(resp(dissect::kSmb2TreeConnect, 1, 0xC00000CC, 0x100001, 7));   // STATUS_BAD_NETWORK_NAME
    EXPECT_EQ(p.t.share(kConn, 0x100001, 7), nullptr);
    p.go(withName(req(dissect::kSmb2Create, 2), "nope"));
    p.go(withFile(resp(dissect::kSmb2Create, 2, 0xC0000034), 4, 4));       // STATUS_OBJECT_NAME_NOT_FOUND: no file
    EXPECT_EQ(p.t.openFile(kConn, 4, 4), nullptr);
    // the same ids on another connection are another file
    const std::string other = dissect::smb2ConnectionKey("10.0.0.9", 445, "10.0.0.1", 50001);
    p.go(withName(req(dissect::kSmb2Create, 1), "here"), 0, kConn);
    p.go(withFile(resp(dissect::kSmb2Create, 1), 8, 8), 0, kConn);
    auto *r = p.go(withFile(req(8, 2), 8, 8), 0, other);
    EXPECT_TRUE(r->file.empty());
    EXPECT_EQ(p.t.openFile(other, 8, 8), nullptr);
    EXPECT_EQ(p.t.connectionCount(), 2u);
}

TEST(Smb2Table, TreeDisconnectLogoffAndNegotiateForgetWhatTheyEnd) {
    Probe p;
    auto open = [&](uint64_t session, uint32_t tree, uint64_t mid, uint64_t fid, const char *share, const char *name) {
        p.go(withName(req(dissect::kSmb2TreeConnect, mid, session), share));
        p.go(resp(dissect::kSmb2TreeConnect, mid, 0, session, tree));
        p.go(withName(req(dissect::kSmb2Create, mid + 1, session, tree), name));
        p.go(withFile(resp(dissect::kSmb2Create, mid + 1, 0, session, tree), fid, fid));
    };
    open(0xA, 1, 10, 100, "\\\\s\\one", "f1");
    open(0xA, 2, 20, 200, "\\\\s\\two", "f2");
    open(0xB, 3, 30, 300, "\\\\s\\three", "f3");
    p.go(req(dissect::kSmb2TreeDisconnect, 40, 0xA, 1));
    p.go(resp(dissect::kSmb2TreeDisconnect, 40, 0, 0xA, 1));
    EXPECT_EQ(p.t.share(kConn, 0xA, 1), nullptr);
    EXPECT_EQ(p.t.openFile(kConn, 100, 100), nullptr);
    EXPECT_NE(p.t.openFile(kConn, 200, 200), nullptr) << "the other tree of the session stays";
    p.go(req(dissect::kSmb2Logoff, 41, 0xA));
    p.go(resp(dissect::kSmb2Logoff, 41, 0, 0xA));
    EXPECT_EQ(p.t.share(kConn, 0xA, 2), nullptr);
    EXPECT_EQ(p.t.openFile(kConn, 200, 200), nullptr);
    EXPECT_NE(p.t.openFile(kConn, 300, 300), nullptr) << "another session is untouched";
    p.go(req(dissect::kSmb2Negotiate, 0, 0));
    EXPECT_EQ(p.t.openFile(kConn, 300, 300), nullptr);
    EXPECT_EQ(p.t.share(kConn, 0xB, 3), nullptr);
}

TEST(Smb2Table, NamedPipesAreFilesOfAnIpcShare) {
    Probe p;
    p.go(withName(req(dissect::kSmb2TreeConnect, 1), "\\\\10.0.0.2\\ipc$"));
    auto *tc = p.go(resp(dissect::kSmb2TreeConnect, 1, 0, 0x100001, 3));
    EXPECT_TRUE(tc->flags & Smb2Note::kPipe);
    auto *c = p.go(withName(req(dissect::kSmb2Create, 2, 0x100001, 3), "srvsvc"));
    EXPECT_TRUE(c->flags & Smb2Note::kPipe);
    p.go(withFile(resp(dissect::kSmb2Create, 2, 0, 0x100001, 3), 0x44, 0x55));
    ASSERT_NE(p.t.openFile(kConn, 0x44, 0x55), nullptr);
    EXPECT_TRUE(p.t.openFile(kConn, 0x44, 0x55)->pipe);
    EXPECT_EQ(p.t.openFile(kConn, 0x44, 0x55)->name, "srvsvc");
    auto *w = p.go(withFile(req(9, 3, 0x100001, 3), 0x44, 0x55));
    EXPECT_TRUE(w->flags & Smb2Note::kPipe);
    // a share type of 2 in the response is a pipe whatever its name
    p.go(withName(req(dissect::kSmb2TreeConnect, 4), "\\\\10.0.0.2\\pipes"));
    Smb2Command r = resp(dissect::kSmb2TreeConnect, 4, 0, 0x100001, 4);
    r.shareType = 2;
    EXPECT_TRUE(p.go(r)->flags & Smb2Note::kPipe);
    // a disk share is not
    p.go(withName(req(dissect::kSmb2TreeConnect, 5), "\\\\10.0.0.2\\data"));
    EXPECT_FALSE(p.go(resp(dissect::kSmb2TreeConnect, 5, 0, 0x100001, 5))->flags & Smb2Note::kPipe);
}

TEST(Smb2Table, AskingTwiceForTheSameCommandDoesNotChangeTheState) {
    Probe p;
    p.go(withName(req(dissect::kSmb2Create, 1), "x"));   // packet 1
    const Smb2Command r = withFile(resp(dissect::kSmb2Create, 1), 9, 9);
    const Smb2Note *first = p.t.observe(kConn, 2, 0, 0, r, kBig, p.lost);
    const size_t memory = p.t.memory();
    const Smb2Note *second = p.t.observe(kConn, 2, 0, 0, r, kBig, p.lost);
    EXPECT_EQ(first, second);
    EXPECT_EQ(p.t.memory(), memory);
    EXPECT_FALSE(second->flags & Smb2Note::kUnmatched);
}

TEST(Smb2Table, CancelAndUnsolicitedMessagesAreNeverPending) {
    Probe p;
    p.go(req(8, 5));
    p.go(req(dissect::kSmb2Cancel, 5));
    auto *r = p.go(resp(8, 5));
    EXPECT_TRUE(r->flags & Smb2Note::kMatched) << "Cancel reuses the id of the request it cancels and must not replace it";
    EXPECT_EQ(r->requestPacket, 1u);
    auto *oplock = p.go(resp(0x12, kAll));
    EXPECT_FALSE(oplock->flags & (Smb2Note::kMatched | Smb2Note::kUnmatched));
}

TEST(Smb2Table, TheMemoryBudgetStopsStoringAndTheOldestPendingRequestIsDropped) {
    {
        dissect::Smb2Table t;
        bool lost = false;
        size_t stored = 0;
        for (uint32_t i = 1; i <= 200; ++i) {
            if (t.observe(kConn, i, 0, 0, withName(req(dissect::kSmb2Create, i), "file-" + std::to_string(i)), 4096, lost)) ++stored;
        }
        EXPECT_TRUE(lost);
        EXPECT_GT(stored, 0u);
        EXPECT_LT(stored, 200u);
        EXPECT_LE(t.memory(), 4096u);
    }
    {
        dissect::Smb2Table t;
        bool lost = false;
        for (uint64_t i = 1; i <= dissect::Smb2Table::kMaxPendingPerConnection + 5; ++i) t.observe(kConn, static_cast<uint32_t>(i), 0, 0, req(8, i), kBig, lost);
        EXPECT_TRUE(lost);
        bool l2 = false;
        // MessageId 1 was dropped; the newest is still matched
        EXPECT_TRUE(t.observe(kConn, 99999, 0, 0, resp(8, 1), kBig, l2)->flags & Smb2Note::kUnmatched);
        EXPECT_TRUE(t.observe(kConn, 100000, 0, 0, resp(8, dissect::Smb2Table::kMaxPendingPerConnection + 5), kBig, l2)->flags & Smb2Note::kMatched);
    }
}

TEST(Smb2Table, SessionTablesFreezeRefusesAndTheBudgetMarksStateLost) {
    dissect::SessionTables tables;
    ASSERT_NE(tables.observeSmb2(kConn, 1, 0, 0, withName(req(dissect::kSmb2Create, 1), "x")), nullptr);
    EXPECT_NE(tables.smb2Note(1, 0, 0), nullptr);
    EXPECT_FALSE(tables.hasStateLost());
    tables.freeze();
    EXPECT_EQ(tables.observeSmb2(kConn, 2, 0, 0, req(8, 2)), nullptr);
    EXPECT_NE(tables.smb2Note(1, 0, 0), nullptr) << "Replay reads";
    EXPECT_EQ(tables.smb2Note(2, 0, 0), nullptr);
    tables.clear();
    EXPECT_EQ(tables.smb2Note(1, 0, 0), nullptr);

    dissect::SessionTables small(300);
    for (uint32_t i = 1; i < 20; ++i) small.observeSmb2(kConn, i, 0, 0, withName(req(dissect::kSmb2Create, i), "name-" + std::to_string(i)));
    EXPECT_TRUE(small.isTableStateLost("smb2"));
}

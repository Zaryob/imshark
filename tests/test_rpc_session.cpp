// The ONC RPC session table (onc_rpc_session.h) on its own: record assembly from fragments, call / reply matching by xid,
// retransmissions, replies that come before their call, the portmapper's port map and the memory budget. The expectations follow
// RFC 5531 section 9 (xid matching) and section 11 (record fragments); the table has no wire bytes to check, so the oracle is the
// protocol rules written out in each test.
#include <gtest/gtest.h>

#include <dissect/onc_rpc_session.h>

using dissect::RpcMapping;
using dissect::RpcMessage;
using dissect::RpcNote;
using dissect::RpcTable;

namespace {
    constexpr size_t kBig = 1u << 20;

    struct Table {
        RpcTable t;
        bool lost = false;
        // a TCP fragment of `stream`: sequence number of its mark, body, last-fragment bit
        const RpcNote *frag(const std::string &stream, uint32_t packet, uint32_t seq, const std::string &body, bool last) {
            return t.observeFragment(stream, packet, seq, body, last, seq + 4 + static_cast<uint32_t>(body.size()), kBig, lost);
        }
        const RpcNote *datagram(uint32_t packet) { return t.observeFragment("", packet, -1, "x", true, 0, kBig, lost); }
        const RpcNote *call(uint32_t packet, int64_t seq, uint32_t xid, uint32_t proc, bool fromLow = true, uint32_t vers = 3) {
            RpcMessage m;
            m.call = true; m.xid = xid; m.prog = 100003; m.vers = vers; m.proc = proc;
            return t.observeMessage("a|b", fromLow, packet, seq, m, kBig, lost);
        }
        const RpcNote *reply(uint32_t packet, int64_t seq, uint32_t xid, bool fromLow = false) {
            RpcMessage m;
            m.xid = xid;
            return t.observeMessage("a|b", fromLow, packet, seq, m, kBig, lost);
        }
    };
}

TEST(RpcTable, ADatagramAndAOneFragmentRecordAreCompleteOnTheirOwn) {
    Table x;
    const RpcNote *d = x.datagram(1);
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->flags, RpcNote::kCompletes);
    EXPECT_EQ(d->fragments, 1);
    const RpcNote *r = x.frag("c>s", 2, 1000, "abcd", true);
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->flags, RpcNote::kCompletes);
    EXPECT_EQ(x.t.openRecords(), 0u);
    EXPECT_EQ(x.t.note(2, 1000), r);
    EXPECT_EQ(x.t.note(1, -1), d);
}

TEST(RpcTable, FragmentsOfOneRecordAreJoinedInTheOrderTheyFollowEachOtherInTheStream) {
    Table x;
    const RpcNote *a = x.frag("c>s", 1, 1000, "AAAA", false);
    const RpcNote *b = x.frag("c>s", 2, 1008, "BBBBBB", false);
    const RpcNote *c = x.frag("c>s", 3, 1018, "CC", true);
    EXPECT_EQ(a->flags, RpcNote::kFragment);
    EXPECT_EQ(b->flags, RpcNote::kFragment | RpcNote::kContinuation);
    EXPECT_EQ(c->flags, RpcNote::kFragment | RpcNote::kContinuation | RpcNote::kCompletes);
    EXPECT_EQ(c->fragments, 3);
    const auto *rec = x.t.record(c->record);
    ASSERT_NE(rec, nullptr);
    EXPECT_EQ(rec->bytes, "AAAABBBBBBCC");
    EXPECT_EQ(rec->total, 12u);
    EXPECT_EQ(rec->lastStart, 10u);
    EXPECT_EQ(rec->packets, (std::vector<uint32_t>{1, 2, 3}));
    EXPECT_EQ(x.t.openRecords(), 0u);
    EXPECT_FALSE(x.lost);
}

TEST(RpcTable, TheTwoDirectionsAndOtherConnectionsKeepTheirOwnRecords) {
    Table x;
    x.frag("c>s", 1, 1000, "AAAA", false);
    x.frag("s>c", 2, 5000, "RRRR", false);
    const RpcNote *end = x.frag("c>s", 3, 1008, "BB", true);
    EXPECT_EQ(x.t.record(end->record)->bytes, "AAAABB");
    EXPECT_EQ(x.t.openRecords(), 1u) << "the server's record is still open";
    const RpcNote *other = x.frag("c2>s", 4, 1008, "ZZ", true);
    EXPECT_EQ(other->flags, RpcNote::kCompletes) << "a record of its own";
}

TEST(RpcTable, AStreamThatDoesNotContinueDropsTheOpenRecord) {
    Table x;
    x.frag("c>s", 1, 1000, "AAAA", false);
    // the next fragment starts 100 bytes later: bytes were given up in between (or a new connection reused the ports)
    const RpcNote *n = x.frag("c>s", 2, 1108, "BB", true);
    EXPECT_NE(n->flags & RpcNote::kDropped, 0);
    EXPECT_NE(n->flags & RpcNote::kCompletes, 0);
    EXPECT_EQ(n->fragments, 1) << "it is a record of its own now";
    EXPECT_EQ(x.t.openRecords(), 0u);
}

TEST(RpcTable, WithoutASequenceNumberEveryFragmentStandsAlone) {
    Table x;
    const RpcNote *n = x.t.observeFragment("c>s", 1, -1, "AAAA", false, 0, kBig, x.lost);
    EXPECT_EQ(n->flags, RpcNote::kCompletes);
    EXPECT_EQ(x.t.openRecords(), 0u);
}

TEST(RpcTable, OnlyTheStartOfALongRecordIsKept) {
    Table x;
    const std::string big(RpcTable::kMaxKeptBytes - 10, 'a');
    x.frag("c>s", 1, 0, big, false);
    const RpcNote *n = x.frag("c>s", 2, static_cast<uint32_t>(4 + big.size()), std::string(100, 'b'), true);
    const auto *rec = x.t.record(n->record);
    ASSERT_NE(rec, nullptr);
    EXPECT_EQ(rec->bytes.size(), RpcTable::kMaxKeptBytes);
    EXPECT_EQ(rec->total, big.size() + 100);
    EXPECT_EQ(rec->lastStart, big.size());
    EXPECT_EQ(rec->bytes.substr(rec->bytes.size() - 10), std::string(10, 'b'));
}

TEST(RpcTable, ARecordWithTooManyFragmentsIsDroppedAndSaysSo) {
    Table y;
    uint32_t s = 0;
    const RpcNote *n = nullptr;
    for (uint32_t i = 1; i <= RpcTable::kMaxFragments; ++i) {
        n = y.t.observeFragment("c>s", i, s, "a", false, s + 5, 1u << 30, y.lost);
        s += 5;
    }
    EXPECT_FALSE(y.lost);
    EXPECT_EQ(y.t.openRecords(), 1u);
    n = y.t.observeFragment("c>s", RpcTable::kMaxFragments + 1, s, "a", false, s + 5, 1u << 30, y.lost);
    EXPECT_NE(n->flags & RpcNote::kDropped, 0);
    EXPECT_TRUE(y.lost);
    EXPECT_EQ(y.t.openRecords(), 0u);
}

TEST(RpcTable, ACallIsFoundAgainByItsReply) {
    Table x;
    x.datagram(1); x.datagram(2);
    const RpcNote *c = x.call(1, -1, 7, 6);
    EXPECT_EQ(c->prog, 100003u);
    EXPECT_EQ(c->proc, 6u);
    EXPECT_EQ(c->flags & RpcNote::kMatched, 0);
    const RpcNote *r = x.reply(2, -1, 7);
    EXPECT_NE(r->flags & RpcNote::kMatched, 0);
    EXPECT_EQ(r->callPacket, 1u);
    EXPECT_EQ(r->vers, 3u);
    EXPECT_EQ(r->proc, 6u);
    EXPECT_EQ(x.t.note(1, -1)->replyPacket, 2u) << "the call learns its reply (shown in the detail tree)";
}

TEST(RpcTable, AReplyOfTheOtherXidOrTheSameSideIsNotAMatch) {
    Table x;
    x.datagram(1); x.datagram(2); x.datagram(3);
    x.call(1, -1, 7, 6);
    EXPECT_EQ(x.reply(2, -1, 8)->flags & RpcNote::kMatched, 0);
    EXPECT_EQ(x.reply(3, -1, 7, true)->flags & RpcNote::kMatched, 0) << "a reply comes from the side that was called";
}

TEST(RpcTable, ACallSeenAgainIsARetransmissionAndItsSecondReplyADuplicate) {
    Table x;
    for (uint32_t i = 1; i <= 4; ++i) x.datagram(i);
    x.call(1, -1, 7, 6);
    const RpcNote *again = x.call(2, -1, 7, 6);
    EXPECT_NE(again->flags & RpcNote::kRetransmission, 0);
    EXPECT_EQ(again->callPacket, 1u);
    const RpcNote *first = x.reply(3, -1, 7);
    EXPECT_EQ(first->flags & RpcNote::kDuplicateReply, 0);
    const RpcNote *second = x.reply(4, -1, 7);
    EXPECT_NE(second->flags & RpcNote::kDuplicateReply, 0);
    EXPECT_NE(second->flags & RpcNote::kMatched, 0);
    EXPECT_EQ(x.t.note(1, -1)->replyPacket, 3u) << "the first reply stays";
}

TEST(RpcTable, AReplyThatComesBeforeItsCallStaysUnmatchedWhateverFollows) {
    Table x;
    for (uint32_t i = 1; i <= 4; ++i) x.datagram(i);
    const RpcNote *early = x.reply(1, -1, 7);
    EXPECT_EQ(early->flags & RpcNote::kMatched, 0);
    x.call(2, -1, 7, 6);                                       // the call, retransmitted after the reply
    const RpcNote *r = x.reply(3, -1, 7);
    EXPECT_NE(r->flags & RpcNote::kMatched, 0);
    EXPECT_EQ(r->callPacket, 2u);
    EXPECT_EQ(x.t.note(1, -1)->flags & RpcNote::kMatched, 0) << "the early reply is not matched retroactively";
    EXPECT_EQ(x.t.note(1, -1)->callPacket, 0u);
}

TEST(RpcTable, ACallThatReusesTheXidWithAnotherProcedureReplacesTheOldOne) {
    Table x;
    for (uint32_t i = 1; i <= 3; ++i) x.datagram(i);
    x.call(1, -1, 7, 6);
    const RpcNote *c = x.call(2, -1, 7, 7);
    EXPECT_EQ(c->flags & RpcNote::kRetransmission, 0);
    const RpcNote *r = x.reply(3, -1, 7);
    EXPECT_EQ(r->proc, 7u);
    EXPECT_EQ(r->callPacket, 2u);
}

TEST(RpcTable, TheArgumentsOfACallComeBackWithItsReply) {
    Table x;
    x.datagram(1); x.datagram(2);
    RpcMessage m;
    m.call = true; m.xid = 9; m.prog = 100000; m.vers = 3; m.proc = 3; m.mapProg = 100003; m.mapVers = 4; m.mapProt = 6; m.netid = "tcp";
    x.t.observeMessage("a|b", true, 1, -1, m, kBig, x.lost);
    RpcMessage r;
    r.xid = 9;
    const RpcNote *n = x.t.observeMessage("a|b", false, 2, -1, r, kBig, x.lost);
    EXPECT_EQ(n->mapProg, 100003u);
    EXPECT_EQ(n->mapVers, 4u);
    EXPECT_EQ(n->mapProt, 6u);
    EXPECT_EQ(n->netid, "tcp");
}

TEST(RpcTable, AskingTwiceAnswersTheSameWithoutChangingTheState) {
    Table x;
    x.datagram(1); x.datagram(2);
    x.call(1, -1, 7, 6);
    const RpcNote *r = x.reply(2, -1, 7);
    const size_t mem = x.t.memory();
    EXPECT_EQ(x.reply(2, -1, 7), r);
    EXPECT_EQ(x.datagram(2), r);
    EXPECT_EQ(x.t.memory(), mem);
    EXPECT_EQ(x.call(1, -1, 7, 6)->flags & RpcNote::kRetransmission, 0) << "the call's own packet is not a retransmission of itself";
}

TEST(RpcTable, TheOldestCallsAreForgottenFirstWhenThereAreTooMany) {
    Table x;
    RpcTable &t = x.t;
    for (uint32_t i = 1; i <= RpcTable::kMaxCalls + 5; ++i) {
        t.observeFragment("", i, -1, "x", true, 0, 1u << 30, x.lost);
        RpcMessage m;
        m.call = true; m.xid = i; m.prog = 100003; m.vers = 3; m.proc = 1;
        t.observeMessage("a|b", true, i, -1, m, 1u << 30, x.lost);
    }
    EXPECT_EQ(t.callCount(), RpcTable::kMaxCalls);
    EXPECT_TRUE(x.lost);
    t.observeFragment("", 900000, -1, "x", true, 0, 1u << 30, x.lost);
    RpcMessage r;
    r.xid = 1;
    EXPECT_EQ(t.observeMessage("a|b", false, 900000, -1, r, 1u << 30, x.lost)->flags & RpcNote::kMatched, 0) << "the first call is gone";
    t.observeFragment("", 900001, -1, "x", true, 0, 1u << 30, x.lost);
    r.xid = RpcTable::kMaxCalls + 5;
    EXPECT_NE(t.observeMessage("a|b", false, 900001, -1, r, 1u << 30, x.lost)->flags & RpcNote::kMatched, 0);
}

TEST(RpcTable, ThePortMapIsValidFromTheAnswerOnAndHasOneProgramPerPort) {
    Table x;
    bool lost = false;
    x.t.learnPorts(10, "10.0.0.2", {{100005, 3, 6, 20048, ""}, {100003, 3, 17, 2049, ""}}, kBig, lost);
    EXPECT_FALSE(lost);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 9), nullptr) << "not before the answer";
    const auto *m = x.t.program("10.0.0.2", 20048, false, 10);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->prog, 100005u);
    EXPECT_EQ(m->vers, 3u);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, true, 50), nullptr) << "UDP is another port";
    EXPECT_EQ(x.t.program("10.0.0.3", 20048, false, 50), nullptr) << "another host";
    ASSERT_NE(x.t.program("10.0.0.2", 2049, true, 50), nullptr);
    // another version behind the same port: the program stays, the version is "several"
    x.t.learnPorts(20, "10.0.0.2", {{100005, 1, 6, 20048, ""}}, kBig, lost);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 15)->vers, 3u) << "earlier packets keep what they saw";
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 25)->prog, 100005u);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 25)->vers, 0u);
    // another program: ambiguous, none is guessed
    x.t.learnPorts(30, "10.0.0.2", {{100021, 4, 6, 20048, ""}}, kBig, lost);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 35)->prog, 0u);
    x.t.learnPorts(40, "10.0.0.2", {{100005, 3, 6, 20048, ""}}, kBig, lost);
    EXPECT_EQ(x.t.program("10.0.0.2", 20048, false, 45)->prog, 0u) << "ambiguous stays ambiguous";
}

TEST(RpcTable, OneAnswerThatListsTwoProgramsOnOnePortMakesItAmbiguous) {
    Table x;
    bool lost = false;
    x.t.learnPorts(10, "10.0.0.2", {{100005, 3, 6, 700, ""}, {100021, 4, 6, 700, ""}}, kBig, lost);
    ASSERT_NE(x.t.program("10.0.0.2", 700, false, 10), nullptr);
    EXPECT_EQ(x.t.program("10.0.0.2", 700, false, 10)->prog, 0u);
}

TEST(RpcTable, NonsensePortsAndProtocolsAreNotMapped) {
    Table x;
    bool lost = false;
    x.t.learnPorts(10, "10.0.0.2", {{100005, 3, 6, 0, ""}, {100005, 3, 6, 70000, ""}, {100005, 3, 1, 700, ""}, {0, 3, 6, 700, ""}}, kBig, lost);
    EXPECT_EQ(x.t.portCount(), 0u);
}

TEST(RpcTable, TheHostAnAnswerNamesIsMappedAsWellWhenItIsAnotherOne) {
    Table x;
    bool lost = false;
    x.t.learnPorts(10, "10.0.0.2", {{100005, 3, 6, 700, "10.0.0.9"}, {100005, 3, 6, 701, "0.0.0.0"}}, kBig, lost);
    EXPECT_NE(x.t.program("10.0.0.9", 700, false, 10), nullptr);
    EXPECT_NE(x.t.program("10.0.0.2", 700, false, 10), nullptr);
    EXPECT_EQ(x.t.program("0.0.0.0", 701, false, 10), nullptr);
    EXPECT_NE(x.t.program("10.0.0.2", 701, false, 10), nullptr);
}

TEST(RpcTable, TheBudgetRunsOutAndTheTableSaysSo) {
    RpcTable small;
    bool lost = false;
    EXPECT_EQ(small.observeFragment("", 1, -1, "x", true, 0, 50, lost), nullptr);
    EXPECT_TRUE(lost);
    RpcTable tiny;
    lost = false;
    size_t used = 0;
    for (uint32_t i = 1; i < 3000 && !lost; ++i) {
        tiny.observeFragment("c>s", i, i * 200, std::string(100, 'x'), false, i * 200 + 104, 20000, lost);
        used = tiny.memory();
    }
    EXPECT_TRUE(lost);
    EXPECT_LE(used, 20000u);
}

TEST(RpcTable, AClearedTableForgetsEverything) {
    Table x;
    x.datagram(1);
    x.call(1, -1, 7, 6);
    x.frag("c>s", 2, 0, "ab", false);
    bool lost = false;
    x.t.learnPorts(3, "10.0.0.2", {{100005, 3, 6, 700, ""}}, kBig, lost);
    ASSERT_GT(x.t.memory(), 0u);
    x.t.clear();
    EXPECT_EQ(x.t.memory(), 0u);
    EXPECT_EQ(x.t.noteCount(), 0u);
    EXPECT_EQ(x.t.callCount(), 0u);
    EXPECT_EQ(x.t.openRecords(), 0u);
    EXPECT_EQ(x.t.portCount(), 0u);
}

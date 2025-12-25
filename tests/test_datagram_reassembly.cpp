#include <gtest/gtest.h>

#include <algorithm>
#include <numeric>
#include <random>

#include <network/datagram_reassembly.h>

namespace {
    using network::DatagramFragment;
    using network::DatagramReassembler;

    DatagramFragment frag(uint32_t offset, const std::string &data, uint32_t total, uint32_t number = 0, double time = 0) {
        DatagramFragment f;
        f.offset = offset;
        f.totalLength = total;
        f.data.assign(data.begin(), data.end());
        f.packetNumber = number;
        f.time = time;
        return f;
    }
    std::string str(const std::vector<char> &v) { return std::string(v.begin(), v.end()); }
} // namespace

TEST(DatagramReassembly, UnfragmentedAndEmptyMessagesCompleteAtOnce) {
    DatagramReassembler r;
    auto one = r.add("k", frag(0, "whole", 5, 7));
    ASSERT_TRUE(one.complete);
    EXPECT_EQ(str(one.message), "whole");
    EXPECT_EQ(one.packetNumbers, (std::vector<uint32_t>{7}));
    EXPECT_EQ(r.pendingMessages(), 0u);

    auto empty = r.add("k", frag(0, "", 0, 8));   // DTLS HelloRequest / ServerHelloDone
    ASSERT_TRUE(empty.complete);
    EXPECT_TRUE(empty.message.empty());
    EXPECT_EQ(empty.packetNumbers, (std::vector<uint32_t>{8}));
}

TEST(DatagramReassembly, EveryArrivalOrderGivesTheSameMessage) {
    const std::string whole = "AAAABBBBCCCCDD";
    const std::vector<std::pair<uint32_t, uint32_t>> parts = {{0, 4}, {4, 4}, {8, 4}, {12, 2}};
    std::vector<int> order = {0, 1, 2, 3};
    int permutations = 0;
    do {
        DatagramReassembler r;
        DatagramReassembler::Result last;
        for (size_t i = 0; i < order.size(); ++i) {
            const auto &p = parts[order[i]];
            last = r.add("k", frag(p.first, whole.substr(p.first, p.second), 14, 10 + order[i]));
            EXPECT_EQ(last.complete, i + 1 == order.size());
        }
        ASSERT_TRUE(last.complete);
        EXPECT_EQ(str(last.message), whole);
        ASSERT_EQ(last.packetNumbers.size(), 4u);
        for (size_t i = 0; i < order.size(); ++i) EXPECT_EQ(last.packetNumbers[i], 10u + order[i]) << "arrival order";
        EXPECT_EQ(r.pendingMessages(), 0u);
        EXPECT_EQ(r.pendingBytes(), 0u);
        ++permutations;
    } while (std::next_permutation(order.begin(), order.end()));
    EXPECT_EQ(permutations, 24);
}

TEST(DatagramReassembly, MissingFragmentsKeepTheMessagePending) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 12, 1)).complete);
    EXPECT_FALSE(r.add("k", frag(8, "CCCC", 12, 2)).complete) << "a hole in the middle";
    EXPECT_EQ(r.pendingMessages(), 1u);
    EXPECT_EQ(r.pendingBytes(), 8u);
    auto done = r.add("k", frag(4, "BBBB", 12, 3));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "AAAABBBBCCCC");
}

TEST(DatagramReassembly, KeysAreIndependent) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("a", frag(0, "AA", 4, 1)).complete);
    EXPECT_FALSE(r.add("b", frag(0, "11", 4, 2)).complete);
    EXPECT_EQ(r.pendingMessages(), 2u);
    auto a = r.add("a", frag(2, "aa", 4, 3));
    ASSERT_TRUE(a.complete);
    EXPECT_EQ(str(a.message), "AAaa");
    EXPECT_EQ(a.packetNumbers, (std::vector<uint32_t>{1, 3}));
    EXPECT_EQ(r.pendingMessages(), 1u);
    auto b = r.add("b", frag(2, "22", 4, 4));
    ASSERT_TRUE(b.complete);
    EXPECT_EQ(str(b.message), "1122");
}

TEST(DatagramReassembly, DuplicatesAreHarmless) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 6, 1)).complete);
    auto dup = r.add("k", frag(0, "AAAA", 6, 2));
    EXPECT_FALSE(dup.complete);
    EXPECT_FALSE(dup.conflictingOverlap) << "an identical copy is not a conflict";
    EXPECT_EQ(r.pendingBytes(), 4u) << "no byte is stored twice";
    auto done = r.add("k", frag(4, "BB", 6, 3));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "AAAABB");
    EXPECT_FALSE(done.conflictingOverlap);
    EXPECT_EQ(done.packetNumbers, (std::vector<uint32_t>{1, 2, 3}));

    // the same packet twice (a fragment seen again) is listed once
    DatagramReassembler s;
    EXPECT_FALSE(s.add("k", frag(0, "AA", 4, 5)).complete);
    EXPECT_FALSE(s.add("k", frag(0, "AA", 4, 5)).complete);
    auto d2 = s.add("k", frag(2, "BB", 4, 6));
    ASSERT_TRUE(d2.complete);
    EXPECT_EQ(d2.packetNumbers, (std::vector<uint32_t>{5, 6}));
}

TEST(DatagramReassembly, AgreeingOverlapCompletesWithoutAFlag) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAAAA", 8, 1)).complete);
    auto done = r.add("k", frag(4, "AABB", 8, 2));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "AAAAAABB");
    EXPECT_FALSE(done.conflictingOverlap);
}

TEST(DatagramReassembly, ConflictingOverlapKeepsTheFirstCopyAndIsFlagged) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAAAA", 8, 1)).complete);
    auto done = r.add("k", frag(4, "xxBB", 8, 2));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "AAAAAABB") << "bytes 4 and 5 stay with the first copy";
    EXPECT_TRUE(done.conflictingOverlap);

    // flagged on the fragment that disagreed and kept until completion
    DatagramReassembler s;
    EXPECT_FALSE(s.add("k", frag(0, "AAAA", 12, 1)).complete);
    auto bad = s.add("k", frag(2, "zzzz", 12, 2));
    EXPECT_FALSE(bad.complete);
    EXPECT_TRUE(bad.conflictingOverlap);
    EXPECT_EQ(s.pendingBytes(), 6u) << "only the new bytes 4..5 were added";
    auto later = s.add("k", frag(6, "BBBBBB", 12, 3));
    ASSERT_TRUE(later.complete);
    EXPECT_EQ(str(later.message), "AAAAzzBBBBBB");
    EXPECT_TRUE(later.conflictingOverlap) << "the flag stays on the message";
}

TEST(DatagramReassembly, OneFragmentSpanningSeveralStoredPieces) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(2, "bb", 10, 1)).complete);
    EXPECT_FALSE(r.add("k", frag(6, "ff", 10, 2)).complete);
    auto done = r.add("k", frag(0, "ABCDEFGHIJ", 10, 3));   // covers both pieces and the gaps around them
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "ABbbEFffIJ") << "the gaps are filled from the new fragment, stored bytes stay";
    EXPECT_TRUE(done.conflictingOverlap);
    EXPECT_EQ(done.packetNumbers, (std::vector<uint32_t>{1, 2, 3}));
}

TEST(DatagramReassembly, ADifferentTotalDiscardsTheMessage) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 8, 1)).complete);
    auto bad = r.add("k", frag(4, "BBBB", 12, 2));
    EXPECT_FALSE(bad.complete);
    EXPECT_TRUE(bad.totalConflict);
    EXPECT_FALSE(bad.rejected);
    EXPECT_EQ(r.pendingMessages(), 0u) << "the pending message is dropped";
    EXPECT_EQ(r.pendingBytes(), 0u);

    // a later fragment starts over with its own total
    EXPECT_FALSE(r.add("k", frag(0, "CCCC", 8, 3)).complete);
    auto done = r.add("k", frag(4, "DDDD", 8, 4));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "CCCCDDDD");
    EXPECT_FALSE(done.totalConflict);
}

TEST(DatagramReassembly, UnusableFragmentsAreRejectedAndLeaveTheMessageAlone) {
    DatagramReassembler r;
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 8, 1)).complete);
    EXPECT_TRUE(r.add("k", frag(6, "BBBB", 8, 2)).rejected) << "runs past the total";
    EXPECT_TRUE(r.add("k", frag(0xFFFFFFFFu, "BB", 8, 2)).rejected) << "offset + length overflows 32 bits";
    EXPECT_TRUE(r.add("k", frag(9, "B", 8, 2)).rejected) << "starts past the total";
    EXPECT_TRUE(r.add("k", frag(4, "", 8, 2)).rejected) << "empty fragment of a non-empty message";
    EXPECT_TRUE(r.add("new", frag(0, "x", DatagramReassembler::kMaxMessageBytes + 1, 2)).rejected) << "total over the maximum";
    EXPECT_EQ(r.pendingMessages(), 1u);
    EXPECT_EQ(r.pendingBytes(), 4u);
    auto done = r.add("k", frag(4, "BBBB", 8, 3));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.message), "AAAABBBB");
    EXPECT_EQ(done.packetNumbers, (std::vector<uint32_t>{1, 3})) << "rejected fragments do not count";
}

TEST(DatagramReassembly, AFragmentAfterCompletionStartsANewMessage) {
    DatagramReassembler r;
    ASSERT_TRUE(r.add("k", frag(0, "AB", 2, 1)).complete);
    EXPECT_EQ(r.pendingMessages(), 0u);
    EXPECT_FALSE(r.add("k", frag(0, "A", 4, 2)).complete) << "a retransmitted piece of another-length message";
    EXPECT_EQ(r.pendingMessages(), 1u);
}

TEST(DatagramReassembly, TimeoutCountsFromTheFirstFragmentInCaptureTime) {
    DatagramReassembler r(10.0);
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 8, 1, 100.0)).complete);
    EXPECT_FALSE(r.add("k", frag(0, "AAAA", 8, 2, 109.0)).complete) << "a repeat does not extend the life";
    EXPECT_EQ(r.pendingMessages(), 1u);
    EXPECT_EQ(r.timedOutMessages(), 0u);
    // 11 seconds after the first fragment the message is gone: the last half does not complete it
    auto late = r.add("k", frag(4, "BBBB", 8, 3, 111.0));
    EXPECT_FALSE(late.complete);
    EXPECT_EQ(r.timedOutMessages(), 1u);
    EXPECT_EQ(r.pendingMessages(), 1u) << "the late fragment began a new message";
    EXPECT_EQ(r.pendingBytes(), 4u);

    // another key's traffic also expires old messages
    DatagramReassembler s(10.0);
    s.add("old", frag(0, "AA", 4, 1, 0.0));
    s.add("other", frag(0, "BB", 4, 2, 50.0));
    EXPECT_EQ(s.pendingMessages(), 1u);
    EXPECT_EQ(s.timedOutMessages(), 1u);
    // exactly at the limit is still alive
    DatagramReassembler t(10.0);
    t.add("k", frag(0, "AA", 4, 1, 0.0));
    EXPECT_TRUE(t.add("k", frag(2, "BB", 4, 2, 10.0)).complete);
}

TEST(DatagramReassembly, TooManyPendingMessagesEvictTheOldest) {
    DatagramReassembler r(1e9);
    const size_t n = DatagramReassembler::kMaxPending;
    for (size_t i = 0; i < n; ++i) r.add("m" + std::to_string(i), frag(0, "AA", 4, static_cast<uint32_t>(i)));
    EXPECT_EQ(r.pendingMessages(), n);
    EXPECT_EQ(r.evictedMessages(), 0u);
    r.add("extra", frag(0, "AA", 4, 5000));
    EXPECT_EQ(r.pendingMessages(), n);
    EXPECT_EQ(r.evictedMessages(), 1u);
    EXPECT_FALSE(r.add("m0", frag(2, "BB", 4, 6000)).complete) << "m0 was the oldest and is gone";
    // a younger one survived: m2 is still there
    EXPECT_TRUE(r.add("m2", frag(2, "BB", 4, 6001)).complete);
}

TEST(DatagramReassembly, ByteBudgetEvictsTheOldestAndStaysBounded) {
    DatagramReassembler r(1e9);
    const uint32_t part = 8u << 20, total = DatagramReassembler::kMaxMessageBytes;
    const std::string chunk(part, 'x');
    for (int i = 0; i < 12; ++i) {
        r.add("m" + std::to_string(i), frag(0, chunk, total, static_cast<uint32_t>(i)));
        EXPECT_LE(r.pendingBytes(), DatagramReassembler::kMaxPendingBytes);
    }
    EXPECT_EQ(r.pendingMessages(), 8u) << "64 MiB / 8 MiB";
    EXPECT_EQ(r.evictedMessages(), 4u);
    EXPECT_FALSE(r.add("m0", frag(part, chunk, total, 99)).complete) << "the oldest was evicted";
    EXPECT_LE(r.pendingBytes(), DatagramReassembler::kMaxPendingBytes);
    // an existing message that grows also respects the budget (the others give way, it stays)
    DatagramReassembler s(1e9);
    for (int i = 0; i < 7; ++i) s.add("m" + std::to_string(i), frag(0, chunk, total, static_cast<uint32_t>(i)));
    s.add("grow", frag(0, chunk, total, 50));
    ASSERT_EQ(s.pendingMessages(), 8u);
    auto done = s.add("grow", frag(part, chunk, total, 51));
    ASSERT_TRUE(done.complete) << "the growing message is never its own victim";
    EXPECT_EQ(done.message.size(), total);
    EXPECT_LE(s.pendingBytes(), DatagramReassembler::kMaxPendingBytes);
    EXPECT_EQ(s.evictedMessages(), 1u) << "one older message made room for the second half";
}

TEST(DatagramReassembly, LargestMessageIsAccepted) {
    DatagramReassembler r;
    const uint32_t total = DatagramReassembler::kMaxMessageBytes;
    const std::string half(total / 2, 'q');
    EXPECT_FALSE(r.add("k", frag(0, half, total, 1)).complete);
    auto done = r.add("k", frag(total / 2, half, total, 2));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(done.message.size(), total);
}

TEST(DatagramReassembly, FuzzLegalFragmentationsAlwaysRebuildTheOriginal) {
    std::mt19937 rng(0xD7A6E5u);
    for (int round = 0; round < 300; ++round) {
        const uint32_t len = rng() % 200;
        std::string whole(len, '\0');
        for (auto &c: whole) c = static_cast<char>(rng());
        // cut into random pieces, then add some random overlapping copies and duplicates
        std::vector<DatagramFragment> frags;
        uint32_t pos = 0, number = 1;
        while (pos < len) {
            const uint32_t n = 1 + rng() % std::min<uint32_t>(len - pos, 40);
            frags.push_back(frag(pos, whole.substr(pos, n), len, number++));
            pos += n;
        }
        const size_t base = frags.size();
        for (size_t i = 0; i < base && len > 0; ++i) {
            if (rng() % 3 != 0) continue;
            const uint32_t a = rng() % len, n = 1 + rng() % (len - a);
            frags.push_back(frag(a, whole.substr(a, n), len, number++));   // agreeing copy of any range
        }
        std::shuffle(frags.begin(), frags.end(), rng);

        DatagramReassembler r;
        DatagramReassembler::Result done;
        size_t completions = 0;
        for (size_t i = 0; i < frags.size(); ++i) {
            // some junk of the same key and of other keys in between
            DatagramFragment junk = frag(rng(), std::string(rng() % 8, 'j'), rng() % 300, 9999);
            DatagramReassembler::Result j = r.add("other" + std::to_string(rng() % 4), junk);
            EXPECT_FALSE(j.complete && j.message.size() != junk.totalLength);
            auto res = r.add("k", frags[i]);
            EXPECT_FALSE(res.conflictingOverlap) << "all copies agree";
            EXPECT_FALSE(res.totalConflict);
            EXPECT_FALSE(res.rejected);
            if (res.complete) {
                ++completions;
                done = res;
                EXPECT_EQ(str(done.message), whole);
            }
            EXPECT_LE(r.pendingBytes(), DatagramReassembler::kMaxPendingBytes);
        }
        if (len > 0) {
            // fragments are shuffled with agreeing copies: the message completes when its last byte arrives, and
            // later copies start a new (never completing, unless it is whole) message
            EXPECT_GE(completions, 1u) << "round " << round;
            auto sorted = done.packetNumbers;
            std::sort(sorted.begin(), sorted.end());
            EXPECT_TRUE(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end()) << "no repeated packet";
        }
    }
}

TEST(DatagramReassembly, FuzzGarbageNeverCrashesOrBreaksTheBudget) {
    std::mt19937 rng(12345u);
    DatagramReassembler r(5.0);
    double now = 0;
    for (int i = 0; i < 20000; ++i) {
        DatagramFragment f;
        const uint32_t kind = rng() % 6;
        f.totalLength = kind == 0 ? rng() : kind == 1 ? 0 : rng() % 100;       // includes totals over the maximum
        f.offset = kind == 2 ? 0xFFFFFFF0u + rng() % 16 : rng() % 120;         // includes offsets that overflow with the length
        f.data.assign(rng() % 64, static_cast<char>(rng() % 3));               // few distinct bytes: overlaps often agree
        f.packetNumber = static_cast<uint32_t>(i);
        now += (rng() % 100) / 100.0;
        f.time = now;
        auto res = r.add("k" + std::to_string(rng() % 16), f);
        if (res.complete) {
            EXPECT_LE(res.message.size(), DatagramReassembler::kMaxMessageBytes);
            EXPECT_FALSE(res.packetNumbers.empty());
        }
        EXPECT_LE(r.pendingBytes(), DatagramReassembler::kMaxPendingBytes);
        EXPECT_LE(r.pendingMessages(), DatagramReassembler::kMaxPending);
    }
}

TEST(DatagramReassembly, ARetransmittedFragmentAddsNothingAndEvictsNobody) {
    DatagramReassembler r(1e9);
    const uint32_t part = 8u << 20, total = DatagramReassembler::kMaxMessageBytes;
    const std::string chunk(part, 'x');
    for (int i = 0; i < 7; ++i) r.add("m" + std::to_string(i), frag(0, chunk, total, static_cast<uint32_t>(i)));
    r.add("grow", frag(0, chunk, total, 50));
    ASSERT_EQ(r.pendingMessages(), 8u);
    ASSERT_EQ(r.evictedMessages(), 0u);
    // the same 8 MiB again, and a piece inside it: nothing is new, so the budget is not touched
    r.add("grow", frag(0, chunk, total, 51));
    r.add("grow", frag(1000, std::string(4096, 'x'), total, 52));
    EXPECT_EQ(r.pendingMessages(), 8u);
    EXPECT_EQ(r.evictedMessages(), 0u);
    EXPECT_EQ(r.pendingBytes(), 8u * part);
}

TEST(DatagramReassembly, PacketNumbersAreListedOnceInArrivalOrderWhateverTheirOrder) {
    DatagramReassembler r;
    r.add("k", frag(0, "AA", 6, 9));
    r.add("k", frag(0, "AA", 6, 3));    // a retransmission from an earlier-numbered packet
    r.add("k", frag(2, "BB", 6, 9));    // another fragment of packet 9 (several records in one datagram)
    auto done = r.add("k", frag(4, "CC", 6, 5));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(done.packetNumbers, (std::vector<uint32_t>{9, 3, 5}));
}

TEST(DatagramReassembly, PendingSaysWhetherAMessageIsWaiting) {
    DatagramReassembler r;
    EXPECT_FALSE(r.pending("k"));
    r.add("k", frag(0, "AA", 4, 1));
    EXPECT_TRUE(r.pending("k"));
    EXPECT_FALSE(r.pending("other"));
    r.add("k", frag(2, "BB", 4, 2));
    EXPECT_FALSE(r.pending("k")) << "completed messages are gone";
}

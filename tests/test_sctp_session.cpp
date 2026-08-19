// The SCTP session table (dissect/sctp_session.cpp): DATA / I-DATA fragments of one user message put together through the
// datagram reassembler (B2), in any arrival order, with repeats, TSN wrap-around, two streams and unordered messages at once,
// the memory budget, and the per-stream totals.
//
// Oracle: the original message bytes. Every fuzz round cuts a known message into fragments (TSN order, B on the first, E on the
// last), delivers them shuffled with random repeats and expects exactly those bytes back; hand-written expectations elsewhere.
#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <string>
#include <vector>

#include <dissect/session.h>

using dissect::SctpFragment;
using dissect::SctpFragmentRef;
using dissect::SctpTable;

namespace {
    constexpr size_t kBig = 64u << 20;
    const std::string A = "10.0.0.1", B = "10.0.0.2";

    struct Frag {
        std::string bytes;
        SctpFragment f;
    };
    // fragment `i` of an ordered DATA message on `stream`/`ssn`, TSN `tsn0 + i`
    SctpFragment dataFragment(uint32_t packet, uint16_t position, uint16_t stream, uint16_t ssn, uint32_t tsn, bool begin, bool end, const std::string &bytes,
                              bool unordered = false) {
        SctpFragment f;
        f.packet = packet;
        f.position = position;
        f.stream = stream;
        f.ssn = ssn;
        f.sequence = tsn;
        f.begin = begin;
        f.end = end;
        f.unordered = unordered;
        f.ppid = begin ? 51 : 0;
        f.data = bytes.data();
        f.size = bytes.size();
        return f;
    }
    SctpTable::AddResult add(SctpTable &t, const SctpFragment &f, std::vector<uint32_t> &earlier, size_t max = kBig, bool reverse = false) {
        earlier.clear();
        return reverse ? t.addFragment(B, 5000, A, 38412, f, max, earlier) : t.addFragment(A, 38412, B, 5000, f, max, earlier);
    }
}

TEST(SctpTable, ThreeFragmentsInOrderCompleteAtTheLastAndTheEarlierOnesKnowWhere) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    const std::string p1 = "Hello ", p2 = "SCTP ", p3 = "world";
    add(t, dataFragment(1, 12, 1, 0, 100, true, false, p1), earlier);
    EXPECT_EQ(t.fragment(1, 12)->completedIn, 0u);
    add(t, dataFragment(2, 12, 1, 0, 101, false, false, p2), earlier);
    EXPECT_TRUE(earlier.empty());
    add(t, dataFragment(3, 12, 1, 0, 102, false, true, p3), earlier);
    EXPECT_EQ(earlier, (std::vector<uint32_t>{1, 2}));
    const auto *ref = t.fragment(3, 12);
    ASSERT_NE(ref, nullptr);
    EXPECT_TRUE(ref->flags & SctpFragmentRef::kCompletesHere);
    EXPECT_EQ(ref->completedIn, 3u);
    EXPECT_EQ(t.fragment(1, 12)->completedIn, 3u);
    EXPECT_EQ(t.fragment(2, 12)->completedIn, 3u);
    const auto *m = t.message(ref->message);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->data, "Hello SCTP world");
    EXPECT_EQ(m->packets, (std::vector<uint32_t>{1, 2, 3}));
    EXPECT_EQ(m->stream, 1);
    EXPECT_EQ(m->ppid, 51u);
    EXPECT_EQ(t.pendingMessages(), 0u);
}

TEST(SctpTable, EveryArrivalOrderOfFourFragmentsGivesTheSameMessage) {
    const std::vector<std::string> parts = {"aa", "bbb", "c", "dddd"};
    std::vector<int> order = {0, 1, 2, 3};
    int permutations = 0;
    do {
        SctpTable t;
        std::vector<uint32_t> earlier;
        uint32_t completing = 0;
        for (int k = 0; k < 4; ++k) {
            const int i = order[k];
            add(t, dataFragment(10 + k, 8, 2, 7, 500 + i, i == 0, i == 3, parts[i]), earlier);
            if (t.fragment(10 + k, 8)->flags & SctpFragmentRef::kCompletesHere) completing = 10 + k;
        }
        EXPECT_EQ(completing, 13u) << "order " << order[0] << order[1] << order[2] << order[3];   // the last to arrive completes it
        ASSERT_EQ(t.messageCount(), 1u);
        EXPECT_EQ(t.message(0)->data, "aabbbcdddd");
        ++permutations;
    } while (std::next_permutation(order.begin(), order.end()));
    EXPECT_EQ(permutations, 24);
}

TEST(SctpTable, TwoStreamsAndAnUnorderedMessageAreKeptApart) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    // stream 1 SSN 0 (TSN 10,11), stream 2 SSN 0 (TSN 12,13), stream 3 unordered (TSN 14,15), interleaved
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, "one-"), earlier);
    add(t, dataFragment(2, 12, 2, 0, 12, true, false, "two-"), earlier);
    add(t, dataFragment(3, 12, 3, 0, 14, true, false, "three-", true), earlier);
    EXPECT_EQ(t.pendingMessages(), 3u);
    add(t, dataFragment(4, 12, 3, 0, 15, false, true, "unordered", true), earlier);
    add(t, dataFragment(5, 12, 2, 0, 13, false, true, "second", false), earlier);
    add(t, dataFragment(6, 12, 1, 0, 11, false, true, "first"), earlier);
    ASSERT_EQ(t.messageCount(), 3u);
    EXPECT_EQ(t.message(0)->data, "three-unordered");
    EXPECT_EQ(t.message(1)->data, "two-second");
    EXPECT_EQ(t.message(2)->data, "one-first");
    EXPECT_TRUE(t.message(0)->unordered);
    EXPECT_EQ(t.pendingMessages(), 0u);
}

TEST(SctpTable, TheSameSsnInTheOtherDirectionOrOnAnotherStreamIsAnotherMessage) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, "x"), earlier);
    add(t, dataFragment(2, 12, 1, 0, 11, false, true, "y"), earlier, kBig, true);   // other direction: no neighbour there
    add(t, dataFragment(3, 12, 9, 0, 11, false, true, "z"), earlier);               // other stream
    EXPECT_EQ(t.messageCount(), 0u);
    EXPECT_EQ(t.pendingMessages(), 3u);
}

TEST(SctpTable, TsnsWrapAroundTheEndOfTheNumberSpace) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 0xfffffffeu, true, false, "ab"), earlier);
    add(t, dataFragment(3, 12, 1, 0, 0u, false, true, "ef"), earlier);
    add(t, dataFragment(2, 12, 1, 0, 0xffffffffu, false, false, "cd"), earlier);
    ASSERT_EQ(t.messageCount(), 1u);
    EXPECT_EQ(t.message(0)->data, "abcdef");
}

TEST(SctpTable, ARepeatedFragmentIsARetransmissionAndOtherBytesAreAConflict) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, "aaaa"), earlier);
    add(t, dataFragment(2, 12, 1, 0, 10, true, false, "aaaa"), earlier);
    EXPECT_EQ(t.fragment(2, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.fragment(2, 12)->original, 1u);
    add(t, dataFragment(3, 12, 1, 0, 10, true, false, "aaXa"), earlier);
    EXPECT_EQ(t.fragment(3, 12)->flags, SctpFragmentRef::kRetransmission | SctpFragmentRef::kConflict);
    add(t, dataFragment(4, 12, 1, 0, 10, true, false, "aaa"), earlier);
    EXPECT_TRUE(t.fragment(4, 12)->flags & SctpFragmentRef::kConflict);   // another length
    add(t, dataFragment(5, 12, 1, 0, 11, false, true, "bb"), earlier);
    EXPECT_EQ(t.message(0)->data, "aaaabb");           // the first copy won
    // the same packet and position again (a packet dissected twice): ignored
    const size_t refs = t.fragmentCount();
    add(t, dataFragment(5, 12, 1, 0, 11, false, true, "bb"), earlier);
    EXPECT_EQ(t.fragmentCount(), refs);
}

TEST(SctpTable, AFragmentOfAMessageCompletedBeforeIsMarkedAsRetransmission) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, "ab"), earlier);
    add(t, dataFragment(2, 12, 1, 0, 11, false, true, "cd"), earlier);
    add(t, dataFragment(3, 12, 1, 0, 10, true, false, "ab"), earlier);
    EXPECT_EQ(t.fragment(3, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.fragment(3, 12)->original, 2u);
    EXPECT_EQ(t.pendingMessages(), 0u);                // it did not start a message that never completes
    EXPECT_EQ(t.messageCount(), 1u);
}

TEST(SctpTable, IDataFragmentsFollowEachOtherByFsnAndSeveralMessagesShareAStream) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    auto idata = [&](uint32_t packet, uint32_t mid, uint32_t fsn, bool b, bool e, const std::string &bytes) {
        SctpFragment f = dataFragment(packet, 12, 4, 0, 1000 + packet, b, e, bytes);
        f.idata = true;
        f.ssn = mid;
        f.sequence = fsn;
        return f;
    };
    // messages 5 and 6 on stream 4, fragments mixed: TSNs are unrelated to the FSNs
    add(t, idata(1, 6, 0, true, false, "six-"), earlier);
    add(t, idata(2, 5, 1, false, true, "five"), earlier);
    add(t, idata(3, 5, 0, true, false, "5: "), earlier);
    add(t, idata(4, 6, 1, false, false, "mid-"), earlier);
    add(t, idata(5, 6, 2, false, true, "end"), earlier);
    ASSERT_EQ(t.messageCount(), 2u);
    EXPECT_EQ(t.message(0)->data, "5: five");
    EXPECT_TRUE(t.message(0)->idata);
    EXPECT_EQ(t.message(0)->ssn, 5u);
    EXPECT_EQ(t.message(1)->data, "six-mid-end");
    EXPECT_EQ(t.message(1)->packets, (std::vector<uint32_t>{1, 4, 5}));
}

TEST(SctpTable, AMissingFragmentLeavesTheMessagePendingAndEmptyFragmentsAreAccepted) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, "ab"), earlier);
    add(t, dataFragment(2, 12, 1, 0, 12, false, true, "ef"), earlier);
    EXPECT_EQ(t.messageCount(), 0u);
    EXPECT_EQ(t.pendingMessages(), 1u);
    EXPECT_EQ(t.fragment(2, 12)->completedIn, 0u);
    add(t, dataFragment(3, 12, 1, 0, 11, false, false, ""), earlier);      // an empty middle fragment
    ASSERT_EQ(t.messageCount(), 1u);
    EXPECT_EQ(t.message(0)->data, "abef");
    EXPECT_EQ(t.message(0)->packets, (std::vector<uint32_t>{1, 3, 2}));
}

TEST(SctpTable, AMessageOverSixteenMebibytesIsRejectedNotKept) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    const std::string big(10u << 20, 'x');
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, big), earlier);
    const auto r = add(t, dataFragment(2, 12, 1, 0, 11, false, true, big), earlier);
    EXPECT_TRUE(r.kept);
    EXPECT_TRUE(t.fragment(2, 12)->flags & SctpFragmentRef::kRejected);
    EXPECT_EQ(t.messageCount(), 0u);
}

TEST(SctpTable, TheBudgetEvictsTheOldestIncompleteMessageAndRefusesWhenNothingFitsAnyMore) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    const std::string chunk(1000, 'q');
    size_t evicted = 0;
    bool refused = false;
    for (uint32_t i = 0; i < 40; ++i) {
        // 40 incomplete messages (different SSNs), each 1000 bytes, in a 12 KB budget
        const auto r = add(t, dataFragment(100 + i, 12, 1, static_cast<uint16_t>(i), 10 + i, true, false, chunk), earlier, 12000);
        evicted += r.evicted;
        refused = refused || !r.kept;
        EXPECT_LE(t.memory(), 12000u);
    }
    EXPECT_GT(evicted, 0u);
    EXPECT_GT(t.evictedMessages(), 0u);
    EXPECT_LT(t.pendingMessages(), 40u);
    // the oldest are gone: its late partner starts a message of its own that never completes
    add(t, dataFragment(500, 12, 1, 0, 11, false, true, "z"), earlier, 12000);
    EXPECT_EQ(t.messageCount(), 0u);
    // a budget too small for even one fragment
    SctpTable tiny;
    const auto r = add(tiny, dataFragment(1, 12, 1, 0, 10, true, false, chunk), earlier, 100);
    EXPECT_FALSE(r.kept);
    EXPECT_EQ(tiny.fragment(1, 12), nullptr);
    (void) refused;
}

TEST(SctpTable, MessagesAndReferencesCountAgainstTheBudgetAndClearFreesThem) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 1, 0, 10, true, false, std::string(500, 'a')), earlier);
    const size_t pending = t.memory();
    EXPECT_GT(pending, 500u);
    add(t, dataFragment(2, 12, 1, 0, 11, false, true, std::string(500, 'b')), earlier);
    EXPECT_GE(t.memory(), 1000u);     // the message is kept for Replay
    t.clear();
    EXPECT_EQ(t.memory(), 0u);
    EXPECT_EQ(t.messageCount(), 0u);
    EXPECT_EQ(t.fragment(1, 12), nullptr);
}

TEST(SctpTable, StreamTotalsCountEveryChunkOnceAndStreamsPerDirection) {
    SctpTable t;
    EXPECT_TRUE(t.noteData(A, 38412, B, 5000, 1, 10, false, 1, 12, kBig));
    EXPECT_TRUE(t.noteData(A, 38412, B, 5000, 1, 20, true, 2, 12, kBig));
    EXPECT_TRUE(t.noteData(A, 38412, B, 5000, 2, 5, true, 2, 40, kBig));
    EXPECT_TRUE(t.noteData(A, 38412, B, 5000, 2, 5, true, 2, 40, kBig));   // the same chunk again: not counted twice
    EXPECT_TRUE(t.noteData(B, 5000, A, 38412, 1, 7, true, 3, 12, kBig));
    const auto *s1 = t.stream(A, 38412, B, 5000, 1);
    ASSERT_NE(s1, nullptr);
    EXPECT_EQ(s1->chunks, 2u);
    EXPECT_EQ(s1->bytes, 30u);
    EXPECT_EQ(s1->messages, 1u);
    EXPECT_EQ(t.stream(A, 38412, B, 5000, 2)->chunks, 1u);
    EXPECT_EQ(t.streamCount(A, 38412, B, 5000), 2u);
    EXPECT_EQ(t.streamCount(B, 5000, A, 38412), 1u);
    EXPECT_EQ(t.stream(A, 38412, B, 5000, 3), nullptr);
    SctpTable full;
    EXPECT_FALSE(full.noteData(A, 38412, B, 5000, 1, 10, false, 1, 12, 50));
}

TEST(SctpTable, SeededFuzzRebuildsEveryMessageFromShuffledFragmentsWithRepeats) {
    std::mt19937 rng(0x5c7a0001u);
    for (int round = 0; round < 300; ++round) {
        SctpTable t;
        std::vector<uint32_t> earlier;
        const size_t messages = 1 + rng() % 4;
        struct Item { SctpFragment f; std::string bytes; int message; };
        std::vector<std::string> originals;
        std::vector<Item> items;
        uint32_t tsn = rng();                      // may wrap
        uint32_t packet = 1;
        for (size_t m = 0; m < messages; ++m) {
            std::string whole;
            const size_t len = 2 + rng() % 400;
            for (size_t i = 0; i < len; ++i) whole += static_cast<char>('a' + rng() % 26);
            originals.push_back(whole);
            const size_t pieces = 2 + rng() % 5;
            std::vector<size_t> cuts = {0, len};
            for (size_t i = 1; i < pieces; ++i) cuts.push_back(1 + rng() % (len - 1));
            std::sort(cuts.begin(), cuts.end());
            cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());
            for (size_t i = 0; i + 1 < cuts.size(); ++i) {
                Item it;
                it.bytes = whole.substr(cuts[i], cuts[i + 1] - cuts[i]);
                it.f = dataFragment(packet++, 12, static_cast<uint16_t>(m % 2), static_cast<uint16_t>(m), tsn++, i == 0, i + 2 == cuts.size(), "");
                it.message = static_cast<int>(m);
                items.push_back(std::move(it));
            }
        }
        std::vector<size_t> order(items.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::shuffle(order.begin(), order.end(), rng);
        // repeats of some fragments somewhere later (new packet numbers)
        for (size_t i = 0; i < order.size() / 3; ++i) order.insert(order.begin() + rng() % (order.size() + 1), order[rng() % order.size()]);
        std::vector<std::string> seen;
        std::vector<char> used(items.size(), 0);
        for (size_t k : order) {
            auto &it = items[k];
            SctpFragment f = it.f;
            f.packet = 1000 + static_cast<uint32_t>(seen.size());
            seen.emplace_back();
            f.data = it.bytes.data();
            f.size = it.bytes.size();
            add(t, f, earlier);
        }
        std::vector<std::string> got;
        for (size_t i = 0; i < t.messageCount(); ++i) got.push_back(t.message(static_cast<uint32_t>(i))->data);
        std::sort(got.begin(), got.end());
        std::sort(originals.begin(), originals.end());
        ASSERT_EQ(got, originals) << "round " << round;
        EXPECT_EQ(t.pendingMessages(), 0u) << "round " << round;
    }
}

// Review finding: unordered DATA shares one key per stream, so after M1 (TSN 1-2) and M2 (3-4) a retransmission of M1 was not
// recognised (only the last completed range was remembered) and completed a second time.
TEST(SctpTable, ARetransmissionOfAnEarlierUnorderedMessageIsNotAnotherMessage) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    add(t, dataFragment(1, 12, 3, 0, 1, true, false, "m1a", true), earlier);
    add(t, dataFragment(2, 12, 3, 0, 2, false, true, "m1b", true), earlier);
    add(t, dataFragment(3, 12, 3, 0, 3, true, false, "m2a", true), earlier);
    add(t, dataFragment(4, 12, 3, 0, 4, false, true, "m2b", true), earlier);
    ASSERT_EQ(t.messageCount(), 2u);
    add(t, dataFragment(5, 12, 3, 0, 1, true, false, "m1a", true), earlier);
    EXPECT_EQ(t.fragment(5, 12)->flags, SctpFragmentRef::kRetransmission);
    add(t, dataFragment(6, 12, 3, 0, 2, false, true, "m1b", true), earlier);
    EXPECT_EQ(t.fragment(6, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.messageCount(), 2u);
    EXPECT_EQ(t.pendingMessages(), 0u);
    EXPECT_TRUE(earlier.empty());
}

TEST(SctpTable, ARetransmissionOfAnEarlierIDataMessageAndOfOldOrderedOnesIsRecognisedToo) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    auto idata = [&](uint32_t packet, uint32_t mid, uint32_t fsn, bool b, bool e, bool unordered) {
        SctpFragment f = dataFragment(packet, 12, 4, 0, 1000 + packet, b, e, "xy", unordered);
        f.idata = true;
        f.ssn = mid;
        f.sequence = fsn;
        return f;
    };
    add(t, idata(1, 1, 0, true, false, true), earlier);
    add(t, idata(2, 1, 1, false, true, true), earlier);
    add(t, idata(3, 2, 0, true, false, true), earlier);
    add(t, idata(4, 2, 1, false, true, true), earlier);
    ASSERT_EQ(t.messageCount(), 2u);
    add(t, idata(5, 1, 0, true, false, true), earlier);
    add(t, idata(6, 1, 1, false, true, true), earlier);
    EXPECT_EQ(t.fragment(5, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.fragment(6, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.messageCount(), 2u);
    // ordered DATA, many messages later (each its own key), and an unordered stream far later: still recognised
    for (uint16_t ssn = 0; ssn < 50; ++ssn) {
        add(t, dataFragment(10 + 2 * ssn, 12, 1, ssn, 100 + 2 * ssn, true, false, "a"), earlier);
        add(t, dataFragment(11 + 2 * ssn, 12, 1, ssn, 101 + 2 * ssn, false, true, "b"), earlier);
    }
    add(t, dataFragment(500, 12, 1, 0, 100, true, false, "a"), earlier);
    EXPECT_EQ(t.fragment(500, 12)->flags, SctpFragmentRef::kRetransmission);
    EXPECT_EQ(t.messageCount(), 52u);
}

TEST(SctpTable, CompletedRangesMergeAndAreBounded) {
    SctpTable t;
    std::vector<uint32_t> earlier;
    // 600 unordered messages of two fragments each, completed with gaps of one TSN between them: nothing merges, only the last 256
    // ranges are remembered and the table says it forgot
    bool forgot = false;
    for (uint32_t m = 0; m < 600; ++m) {
        add(t, dataFragment(1 + 2 * m, 12, 3, 0, 10 * m, true, false, "a", true), earlier);
        forgot = forgot || add(t, dataFragment(2 + 2 * m, 12, 3, 0, 10 * m + 1, false, true, "b", true), earlier).evicted;
    }
    EXPECT_TRUE(forgot);
    add(t, dataFragment(5000, 12, 3, 0, 10 * 599, true, false, "a", true), earlier);
    EXPECT_EQ(t.fragment(5000, 12)->flags, SctpFragmentRef::kRetransmission);        // recent: remembered
    // adjacent messages (TSN 10000.. in a row) merge into one range, so a long in-order stream is never forgotten
    SctpTable u;
    bool forgotInOrder = false;
    for (uint32_t m = 0; m < 2000; ++m) {
        add(u, dataFragment(1 + 2 * m, 12, 3, 0, 2 * m, true, false, "a", true), earlier);
        forgotInOrder = forgotInOrder || add(u, dataFragment(2 + 2 * m, 12, 3, 0, 2 * m + 1, false, true, "b", true), earlier).evicted;
    }
    EXPECT_FALSE(forgotInOrder);
    add(u, dataFragment(9000, 12, 3, 0, 0, true, false, "a", true), earlier);
    EXPECT_EQ(u.fragment(9000, 12)->flags, SctpFragmentRef::kRetransmission);
}

// Review minor: the walk back to the B fragment made in-order arrival quadratic (40k one byte fragments took 1.6 s).
TEST(SctpTable, ManyTinyFragmentsInEitherOrderAreLinear) {
    for (bool reverse: {false, true}) {
        SctpTable t;
        std::vector<uint32_t> earlier;
        const uint32_t n = 60000;
        for (uint32_t k = 0; k < n; ++k) {
            const uint32_t i = reverse ? n - 1 - k : k;
            add(t, dataFragment(1 + k, 12, 1, 0, i, i == 0, i == n - 1, "x"), earlier);
        }
        ASSERT_EQ(t.messageCount(), 1u) << reverse;
        EXPECT_EQ(t.message(0)->data.size(), n);
    }
}

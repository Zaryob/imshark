#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include <network/ip_reassembly.h>

namespace {
    network::IpFragment frag(uint32_t offset, bool more, const std::string &data, uint32_t number = 0) {
        network::IpFragment f;
        f.offset = offset;
        f.moreFragments = more;
        f.data.assign(data.begin(), data.end());
        f.packetNumber = number;
        return f;
    }
    std::string str(const std::vector<char> &v) { return std::string(v.begin(), v.end()); }
} // namespace

TEST(IpReassembly, InOrderOutOfOrderAndDuplicates) {
    std::vector<char> out;
    EXPECT_TRUE(network::assembleIpv4Payload({frag(0, false, "whole")}, out)) << "an unfragmented-looking last fragment";
    EXPECT_EQ(str(out), "whole");

    EXPECT_TRUE(network::assembleIpv4Payload({frag(0, true, "AAAA"), frag(4, true, "BBBB"), frag(8, false, "CC")}, out));
    EXPECT_EQ(str(out), "AAAABBBBCC");
    EXPECT_TRUE(network::assembleIpv4Payload({frag(8, false, "CC"), frag(0, true, "AAAA"), frag(4, true, "BBBB")}, out));
    EXPECT_EQ(str(out), "AAAABBBBCC");
    EXPECT_TRUE(network::assembleIpv4Payload({frag(0, true, "AAAA"), frag(0, true, "AAAA"), frag(4, false, "BB"), frag(4, false, "BB")}, out));
    EXPECT_EQ(str(out), "AAAABB");
}

TEST(IpReassembly, IncompleteDatagramsAreNotAssembled) {
    std::vector<char> out;
    EXPECT_FALSE(network::assembleIpv4Payload({}, out));
    EXPECT_FALSE(network::assembleIpv4Payload({frag(0, true, "AAAA")}, out)) << "no last fragment yet";
    EXPECT_FALSE(network::assembleIpv4Payload({frag(0, true, "AAAA"), frag(8, false, "CC")}, out)) << "a hole in the middle";
    EXPECT_FALSE(network::assembleIpv4Payload({frag(4, false, "BB")}, out)) << "the beginning is missing";
    EXPECT_FALSE(network::assembleIpv4Payload({frag(0, false, "")}, out)) << "nothing at all";
}

TEST(IpReassembly, TheFirstCopyOfOverlappingBytesWins) {
    std::vector<char> out;
    ASSERT_TRUE(network::assembleIpv4Payload({frag(0, true, "AAAAAA"), frag(4, false, "xxBB")}, out));
    EXPECT_EQ(str(out), "AAAAAABB") << "bytes 4 and 5 stay AAAA..., the new part is bytes 6 and 7";
}

TEST(IpReassembly, CollectsFragmentsAcrossDatagramsInCaptureOrder) {
    network::IpReassembler r;
    EXPECT_FALSE(r.add("k1", frag(0, true, "AAAA", 1)).complete);
    EXPECT_FALSE(r.add("k2", frag(0, true, "1111", 2)).complete) << "another datagram";
    EXPECT_EQ(r.pendingDatagrams(), 2u);
    auto done = r.add("k1", frag(4, false, "BB", 3));
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(str(done.payload), "AAAABB");
    EXPECT_EQ(done.fragmentNumbers, (std::vector<uint32_t>{1, 3}));
    EXPECT_EQ(r.pendingDatagrams(), 1u) << "completed datagrams are released";
    auto second = r.add("k2", frag(4, false, "22", 4));
    EXPECT_TRUE(second.complete);
    EXPECT_EQ(second.fragmentNumbers, (std::vector<uint32_t>{2, 4}));
    EXPECT_EQ(r.pendingDatagrams(), 0u);
}

TEST(IpReassembly, OldIncompleteDatagramsAreEvicted) {
    network::IpReassembler r;
    for (int i = 0; i < 3000; ++i) r.add("k" + std::to_string(i), frag(0, true, "data", static_cast<uint32_t>(i)));
    EXPECT_LE(r.pendingDatagrams(), 1024u);
    // a huge fragment does not grow memory without bound either
    network::IpReassembler big;
    for (int i = 0; i < 100; ++i) big.add("b" + std::to_string(i), frag(0, true, std::string(1 << 20, 'x'), static_cast<uint32_t>(i)));
    EXPECT_LE(big.pendingDatagrams(), 64u);
}

TEST(IpReassembly, RandomisedFragmentationRoundTrips) {
    std::mt19937 rng(77);
    for (int round = 0; round < 200; ++round) {
        std::string original(rng() % 3000 + 1, '\0');
        for (auto &c: original) c = static_cast<char>(rng());
        std::vector<network::IpFragment> frags;
        for (size_t pos = 0; pos < original.size();) {
            const size_t n = std::min<size_t>((rng() % 40 + 1) * 8, original.size() - pos);
            frags.push_back(frag(static_cast<uint32_t>(pos), pos + n < original.size(), original.substr(pos, n)));
            pos += n;
        }
        const size_t unique = frags.size();
        for (size_t i = 0; i < unique; ++i) if (rng() % 4 == 0) frags.push_back(frags[i]);
        std::shuffle(frags.begin(), frags.end(), rng);
        std::vector<char> out;
        ASSERT_TRUE(network::assembleIpv4Payload(frags, out)) << round;
        ASSERT_EQ(str(out), original) << round;

        frags.erase(frags.begin() + static_cast<long>(rng() % frags.size())); // lose one fragment
        bool lostALast = std::none_of(frags.begin(), frags.end(), [](const auto &f) { return !f.moreFragments; });
        const bool stillComplete = network::assembleIpv4Payload(frags, out);
        if (stillComplete) EXPECT_EQ(str(out), original) << "only possible if the lost one was a duplicate";
        (void)lostALast;
    }
}

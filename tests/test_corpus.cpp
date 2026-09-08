// Regression corpus: small synthetic captures (in the repository) and optional real captures (found through
// IMSHARK_CORPUS_DIR) described by tests/corpus/manifest.json. Every file is checked against its recorded SHA-256 and
// expectations, and every packet is pushed through the details builder, the filter, the statistics and the exporter -
// which, in a sanitizer build, makes the corpus a memory safety test of the whole pipeline.
#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include <core.h>
#include <export/export.h>
#include <filter/filter.h>
#include <stats/statistics.h>

#include "json_lite.h"
#include "sha256.h"
#include "support.h"

namespace {
    const std::string kCorpusDir = std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/";

    std::vector<char> readFile(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    testutil::Json loadManifest() {
        const auto bytes = readFile(kCorpusDir + "manifest.json");
        const std::string text(bytes.begin(), bytes.end());
        return testutil::JsonParser(text).parse();
    }

    const packet::Field *findField(const packet::Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) if (auto r = findField(c, prefix)) return r;
        return nullptr;
    }

    void expectRangesInside(const packet::Field &f, size_t frameSize) {
        EXPECT_LE(size_t(f.offset) + f.length, frameSize) << f.text;
        for (const auto &c: f.children) expectRangesInside(c, frameSize);
    }

    // Checks one corpus file against its manifest entry.
    void checkEntry(const testutil::Json &e, const std::string &path) {
        SCOPED_TRACE(e.str("file"));
        const auto bytes = readFile(path);
        ASSERT_FALSE(bytes.empty()) << "cannot read " << path;
        EXPECT_EQ(testutil::Sha256::of(bytes), e.str("sha256")) << "the file differs from the one the manifest describes";
        EXPECT_EQ(bytes.size(), static_cast<size_t>(e.num("size")));

        uint32_t magic = 0;
        std::memcpy(&magic, bytes.data(), std::min<size_t>(4, bytes.size()));
        const bool ng = magic == 0x0A0D0D0A;
        EXPECT_EQ(ng ? "pcapng" : "pcap", e.str("format"));

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        ASSERT_TRUE(ng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message)) << message;

        if (e.has("message_contains")) EXPECT_NE(message.find(e.str("message_contains")), std::string::npos) << "message: " << message;
        else EXPECT_TRUE(message.empty()) << "unexpected message: " << message;

        ASSERT_EQ(packets.size(), static_cast<size_t>(e.num("packets")));

        std::map<std::string, int> histogram;
        std::set<uint32_t> linkTypes;
        int malformed = 0;
        for (const auto &p: packets) {
            histogram[p.protocol]++;
            linkTypes.insert(p.link_type);
            malformed += p.protocol == "Malformed" || p.info.find("[Malformed Packet") != std::string::npos;
        }
        std::map<std::string, int> expected;
        for (const auto &kv: e.at("protocols").members) expected[kv.first] = static_cast<int>(kv.second.number);
        EXPECT_EQ(histogram, expected);
        std::set<uint32_t> expectedLinks;
        for (const auto &l: e.at("link_types").items) expectedLinks.insert(static_cast<uint32_t>(l.number));
        EXPECT_EQ(linkTypes, expectedLinks);
        EXPECT_EQ(malformed, static_cast<int>(e.num("malformed")));

        // individual facts
        for (const auto &fact: e.at("facts").items) {
            const int number = static_cast<int>(fact.num("packet"));
            ASSERT_GE(number, 1);
            ASSERT_LE(static_cast<size_t>(number), packets.size());
            const auto &p = packets[number - 1];
            SCOPED_TRACE("packet " + std::to_string(number));
            if (fact.has("protocol")) EXPECT_EQ(p.protocol, fact.str("protocol"));
            if (fact.has("info_contains")) EXPECT_NE(p.info.find(fact.str("info_contains")), std::string::npos) << p.info;
            if (fact.has("reassembled_in")) EXPECT_EQ(p.reassembled_in, static_cast<uint32_t>(fact.num("reassembled_in")));
            if (fact.has("fcs_length")) EXPECT_EQ(p.fcs_length, static_cast<uint8_t>(fact.num("fcs_length")));
            if (fact.has("time_relative")) EXPECT_NEAR(p.time, fact.num("time_relative"), 1e-6);
        }

        // the whole pipeline on every packet
        std::vector<uint32_t> all(packets.size());
        for (size_t i = 0; i < all.size(); ++i) all[i] = static_cast<uint32_t>(i);
        for (const auto &p: packets) {
            packet::PacketInfo details;
            ASSERT_TRUE(core::buildPacketDetails(path, p, details, &packets, &fp.captureInfo())) << "packet " << p.number;
            EXPECT_EQ(details.protocol, p.protocol) << "packet " << p.number << ": rebuilding one packet must agree with the loading pass";
            EXPECT_EQ(details.info, p.info) << "packet " << p.number;
            for (const auto &l: details.fields) expectRangesInside(l, details.raw_data.size());
        }
        for (const char *expr: {"tcp || udp || ip || ipv6 || arp", "frame.len > 0 && !malformed", "ip.addr == 10.0.0.0/8 || ipv6.addr == 2001:db8::/32"}) {
            auto f = filter::Filter::compile(expr);
            ASSERT_TRUE(f.ok) << expr;
            for (const auto &p: packets) f.filter.matches(p);
        }
        EXPECT_EQ(stats::protocolHierarchy(packets, nullptr).packets, packets.size());
        stats::conversations(packets, nullptr, stats::AddressKind::Tcp);
        stats::endpoints(packets, nullptr, stats::AddressKind::Ipv6);
        stats::expertInfo(packets, nullptr, fp.captureStartEpoch());

        // exporting everything as pcapng and loading it again keeps the packets
        const auto out = (std::filesystem::temp_directory_path() / "imshark_corpus_roundtrip.pcapng").string();
        std::string error;
        ASSERT_TRUE(exporter::exportPackets(path, packets, all, fp.captureStartEpoch(), exporter::Format::Pcapng, out, error)) << error;
        core::FileProcessor again;
        std::vector<packet::PacketInfo> reloaded;
        std::string reloadMessage;
        ASSERT_TRUE(again.processPcapngFile(out, reloaded, reloadMessage)) << reloadMessage;
        EXPECT_EQ(reloaded.size(), packets.size());
        std::remove(out.c_str());
    }
} // namespace

TEST(Corpus, ManifestIsWellFormed) {
    const auto m = loadManifest();
    ASSERT_TRUE(m.has("entries"));
    const auto &entries = m.at("entries").items;
    EXPECT_GE(entries.size(), 14u);
    std::set<std::string> names;
    int synthetic = 0, real = 0;
    for (const auto &e: entries) {
        SCOPED_TRACE(e.str("file"));
        EXPECT_TRUE(names.insert(e.str("file")).second) << "duplicate entry";
        EXPECT_EQ(e.str("sha256").size(), 64u);
        EXPECT_FALSE(e.str("source").empty()) << "every file says where it comes from";
        EXPECT_FALSE(e.str("expectation").empty()) << "and what kind of expectation it has";
        EXPECT_GT(e.num("packets"), 0);
        EXPECT_TRUE(e.has("protocols") && e.has("link_types") && e.has("facts"));
        if (e.str("kind") == "real") {
            ++real;
            EXPECT_TRUE(e.flag("optional"));
            EXPECT_EQ(e.str("source").rfind("https://", 0), 0u) << "a real capture is described by its URL";
        } else {
            ++synthetic;
            EXPECT_EQ(e.str("kind"), "synthetic");
        }
    }
    EXPECT_GE(synthetic, 14);
    EXPECT_GE(real, 5);
}

TEST(Corpus, SyntheticCapturesMatchTheirManifest) {
    const auto m = loadManifest();
    int checked = 0;
    for (const auto &e: m.at("entries").items) {
        if (e.str("kind") != "synthetic") continue;
        checkEntry(e, kCorpusDir + e.str("file"));
        ++checked;
    }
    EXPECT_GE(checked, 14);
}

TEST(Corpus, RealCapturesWhenTheyAreAvailable) {
    const char *dirEnv = std::getenv("IMSHARK_CORPUS_DIR");
    if (!dirEnv) GTEST_SKIP() << "set IMSHARK_CORPUS_DIR to a directory holding the real captures listed in tests/corpus/manifest.json";
    const std::string dir = std::string(dirEnv) + "/";

    const auto m = loadManifest();
    int checked = 0, missing = 0;
    for (const auto &e: m.at("entries").items) {
        if (e.str("kind") != "real") continue;
        const std::string path = dir + e.str("file");
        if (!std::ifstream(path)) { ++missing; std::cout << "[  SKIP  ] " << e.str("file") << " (not in " << dir << ")\n"; continue; }
        checkEntry(e, path);
        ++checked;
    }
    if (checked == 0) GTEST_SKIP() << "none of the real captures was found in " << dir;
    std::cout << "[  INFO  ] " << checked << " real captures checked, " << missing << " not available\n";
}

TEST(Corpus, Sha256MatchesTheStandardTestVectors) {
    auto of = [](const std::string &text) { return testutil::Sha256::of(std::vector<char>(text.begin(), text.end())); };
    EXPECT_EQ(of(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(of("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    EXPECT_EQ(of(std::string(1000000, 'a')), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

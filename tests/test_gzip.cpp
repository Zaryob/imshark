#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include <core.h>
#include <gzip.h>

#include "support.h"

namespace {
    const std::string kDir = std::string(IMSHARK_TEST_DATA_DIR) + "/gzip/";

    std::string slurp(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    // decompresses the fixture to a temp file and returns the content; `error` receives failures
    bool gunzip(const std::string &compressedPath, std::string &content, std::string &error, core::LoadControl *control = nullptr) {
        const auto out = support::tempPath("gunzip_test.out");
        const bool ok = core::gunzipFile(compressedPath, out, error, control);
        content = ok ? slurp(out) : std::string();
        std::remove(out.c_str());
        return ok;
    }

    bool gunzipBytes(const std::string &bytes, std::string &content, std::string &error) {
        const auto in = support::writeTemp("gunzip_in.gz", std::vector<char>(bytes.begin(), bytes.end()));
        const bool ok = gunzip(in, content, error);
        std::remove(in.c_str());
        return ok;
    }
} // namespace

TEST(Gzip, DetectsTheMagicNumber) {
    EXPECT_TRUE(core::isGzipFile(kDir + "hello.gz"));
    EXPECT_FALSE(core::isGzipFile(kDir + "text.txt"));
    EXPECT_FALSE(core::isGzipFile(std::string(IMSHARK_TEST_DATA_DIR) + "/sample.pcap"));
    EXPECT_FALSE(core::isGzipFile("/no/such/file"));
}

TEST(Gzip, EveryKindOfDeflateBlock) {
    const std::string text = slurp(kDir + "text.txt");
    ASSERT_GT(text.size(), 20000u);
    std::string content, error;
    for (const char *name: {"stored.gz", "fixed.gz", "dynamic.gz", "fast.gz"}) {
        SCOPED_TRACE(name);
        ASSERT_TRUE(gunzip(kDir + name, content, error)) << error;
        EXPECT_EQ(content, text);
    }
    ASSERT_TRUE(gunzip(kDir + "random.gz", content, error)) << error;
    EXPECT_EQ(content, slurp(kDir + "random.bin"));
    ASSERT_TRUE(gunzip(kDir + "hello.gz", content, error)) << error;
    EXPECT_EQ(content, "hello world\n");
    ASSERT_TRUE(gunzip(kDir + "empty.gz", content, error)) << error;
    EXPECT_EQ(content, "");
}

TEST(Gzip, LargeOutputUsesTheSlidingWindow) {
    std::string expected(300000, '\0');
    for (size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<char>((i * 7 + i / 251) % 256);
    std::string content, error;
    ASSERT_TRUE(gunzip(kDir + "big.gz", content, error)) << error;
    EXPECT_EQ(content.size(), expected.size());
    EXPECT_EQ(content, expected) << "back-references reach up to 32 KiB behind";
    EXPECT_EQ(core::lastGunzipOutputSize(), expected.size());
}

TEST(Gzip, ConcatenatedMembersAndHeaderFields) {
    std::string content, error;
    ASSERT_TRUE(gunzip(kDir + "multi.gz", content, error)) << error;
    EXPECT_EQ(content, "first member\nsecond member\nthird\n");
    ASSERT_TRUE(gunzip(kDir + "header_fields.gz", content, error)) << error;
    EXPECT_EQ(content, "with all optional header fields\n") << "FEXTRA, FNAME, FCOMMENT and FHCRC are skipped";

    // zero padding after the last member (written by some tools) is ignored
    std::string padded = slurp(kDir + "hello.gz") + std::string(10, '\0');
    ASSERT_TRUE(gunzipBytes(padded, content, error)) << error;
    EXPECT_EQ(content, "hello world\n");
}

TEST(Gzip, DecompressesACaptureThatThenLoads) {
    const auto plain = (std::filesystem::temp_directory_path() / "imshark_gz_sample.pcap").string();
    std::string error;
    core::LoadControl control;
    ASSERT_TRUE(core::gunzipFile(kDir + "../sample.pcap.gz", plain, error, &control)) << error;
    EXPECT_EQ(slurp(plain), slurp(std::string(IMSHARK_TEST_DATA_DIR) + "/sample.pcap")) << "byte for byte the original";
    EXPECT_EQ(control.bytesProcessed, control.totalBytes) << "progress ends at 100%";
    EXPECT_GT(control.totalBytes, 0u);

    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(plain, packets, message)) << message;
    EXPECT_EQ(packets.size(), 16u);
    std::remove(plain.c_str());
}

TEST(Gzip, DamagedFilesAreReported) {
    const std::string good = slurp(kDir + "dynamic.gz");
    std::string content, error;

    EXPECT_FALSE(gunzipBytes("", content, error));
    EXPECT_NE(error.find("empty or not a gzip"), std::string::npos) << error;
    EXPECT_FALSE(gunzipBytes("this is not gzip data at all", content, error));
    EXPECT_NE(error.find("bad magic"), std::string::npos) << error;
    EXPECT_FALSE(gunzipBytes(good.substr(0, good.size() / 2), content, error));
    EXPECT_NE(error.find("end of the compressed data"), std::string::npos) << error;

    std::string badCrc = good;
    badCrc[badCrc.size() - 8] ^= 0x55;               // the CRC-32 in the trailer
    EXPECT_FALSE(gunzipBytes(badCrc, content, error));
    EXPECT_NE(error.find("CRC mismatch"), std::string::npos) << error;

    std::string badSize = good;
    badSize[badSize.size() - 1] ^= 0x01;             // ISIZE
    EXPECT_FALSE(gunzipBytes(badSize, content, error));
    EXPECT_NE(error.find("Size mismatch"), std::string::npos) << error;

    std::string method = good;
    method[2] = 7;
    EXPECT_FALSE(gunzipBytes(method, content, error));
    EXPECT_NE(error.find("compression method"), std::string::npos) << error;

    EXPECT_FALSE(gunzip("/no/such/file.gz", content, error));
    EXPECT_NE(error.find("Failed to open"), std::string::npos);
    EXPECT_FALSE(core::gunzipFile(kDir + "hello.gz", "/no/such/dir/out", error));
    EXPECT_NE(error.find("Cannot write"), std::string::npos);
}

TEST(Gzip, CancellationStopsTheDecompression) {
    core::LoadControl control;
    control.cancelRequested = true;
    std::string content, error;
    EXPECT_FALSE(gunzip(kDir + "big.gz", content, error, &control));
    EXPECT_TRUE(error.empty()) << "a cancel is not an error";
}

TEST(Gzip, RandomCorruptionNeverCrashesOrHangs) {
    std::mt19937 rng(99);
    std::vector<std::string> seeds;
    for (const char *name: {"dynamic.gz", "fixed.gz", "stored.gz", "random.gz", "multi.gz", "big.gz"}) seeds.push_back(slurp(kDir + name));
    for (int i = 0; i < 1500; ++i) {
        std::string data = seeds[rng() % seeds.size()];
        for (unsigned k = 1 + rng() % 6; k > 0; --k) data[rng() % data.size()] = static_cast<char>(rng());
        if (i % 3 == 0) data.resize(rng() % data.size());
        std::string content, error;
        const bool ok = gunzipBytes(data, content, error);
        if (!ok) EXPECT_FALSE(error.empty());   // every failure has an explanation
    }
}

TEST(GzipMemory, DecodesEveryFixtureLikeTheFileVersion) {
    for (const char *name: {"hello.gz", "stored.gz", "fixed.gz", "dynamic.gz", "fast.gz", "random.gz", "empty.gz"}) {
        SCOPED_TRACE(name);
        std::string fromFile, error, fromMemory;
        ASSERT_TRUE(gunzip(kDir + name, fromFile, error)) << error;
        ASSERT_TRUE(core::gunzipMemory(slurp(kDir + name), fromMemory, 1u << 30, error)) << error;
        EXPECT_EQ(fromMemory, fromFile);
    }
}

TEST(GzipMemory, RejectsDamagedTruncatedAndOversizedData) {
    const std::string good = slurp(kDir + "dynamic.gz");
    std::string out, error;
    EXPECT_FALSE(core::gunzipMemory(good.substr(0, good.size() / 2), out, 1u << 30, error));
    EXPECT_FALSE(error.empty());
    std::string damaged = good;
    damaged[damaged.size() / 2] ^= 0x55;
    EXPECT_FALSE(core::gunzipMemory(damaged, out, 1u << 30, error));
    EXPECT_FALSE(core::gunzipMemory("not gzip at all", out, 1u << 30, error));
    EXPECT_FALSE(core::gunzipMemory("", out, 1u << 30, error));
    EXPECT_FALSE(core::gunzipMemory(good, out, 1000, error)) << "a bomb is stopped at the limit";
    EXPECT_NE(error.find("larger"), std::string::npos) << error;
    EXPECT_TRUE(out.empty());
}

namespace {
    // A valid gzip stream of 'a' x (1 + 258 * matches), built from one fixed-Huffman block: a literal followed by
    // length-258 / distance-1 matches (~160:1). Lets the tests exercise the bomb limits without large fixtures.
    std::string makeBomb(unsigned matches) {
        std::string deflate;
        uint32_t acc = 0;
        int nbits = 0;
        auto putBits = [&](uint32_t value, int n, bool msbFirst) {   // deflate packs Huffman codes MSB first, other fields LSB first
            for (int i = 0; i < n; ++i) {
                const uint32_t bit = msbFirst ? (value >> (n - 1 - i)) & 1 : (value >> i) & 1;
                acc |= bit << nbits;
                if (++nbits == 8) { deflate.push_back(static_cast<char>(acc)); acc = 0; nbits = 0; }
            }
        };
        putBits(1, 1, false);                  // final block
        putBits(1, 2, false);                  // fixed Huffman
        putBits(0x30 + 'a', 8, true);          // literal 'a'
        for (unsigned i = 0; i < matches; ++i) {
            putBits(0xC5, 8, true);            // length symbol 285 (258)
            putBits(0, 5, true);               // distance code 0 (1)
        }
        putBits(0, 7, true);                   // end of block (symbol 256)
        if (nbits) deflate.push_back(static_cast<char>(acc));

        const uint32_t size = 1 + 258 * matches;
        uint32_t crc = 0xffffffffu;
        for (uint32_t i = 0; i < size; ++i) {
            crc ^= 'a';
            for (int k = 0; k < 8; ++k) crc = (crc & 1) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
        }
        crc = ~crc;
        std::string out("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", 10);
        out += deflate;
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((crc >> (8 * i)) & 0xff));
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((size >> (8 * i)) & 0xff));
        return out;
    }

    std::string writeBomb(const std::string &name, unsigned matches) {
        const std::string bomb = makeBomb(matches);
        return support::writeTemp(name, std::vector<char>(bomb.begin(), bomb.end()));
    }

    bool fileExists(const std::string &path) { return std::filesystem::exists(core::pathFromUtf8(path)); }
} // namespace

TEST(GzipLimits, TheGeneratedBombIsValidWhenTheLimitsAreLoose) {
    const auto in = writeBomb("bomb_ok.gz", 100);
    const auto out = support::tempPath("bomb_ok.out");
    std::string error;
    core::GunzipLimits limits;
    limits.maxOutput = 1u << 20;
    limits.maxRatio = 0;
    ASSERT_TRUE(core::gunzipFile(in, out, error, nullptr, limits)) << error;
    EXPECT_EQ(std::filesystem::file_size(core::pathFromUtf8(out)), 1u + 258u * 100u);
    std::remove(in.c_str());
    std::remove(out.c_str());
}

TEST(GzipLimits, OutputBeyondTheMaximumSizeFailsCleanlyAndLeavesNoFile) {
    const auto in = writeBomb("bomb_size.gz", 1000);   // 258 KB of output
    const auto out = support::tempPath("bomb_size.out");
    std::string error;
    core::GunzipLimits limits;
    limits.maxOutput = 100000;
    limits.maxRatio = 0;
    EXPECT_FALSE(core::gunzipFile(in, out, error, nullptr, limits));
    EXPECT_NE(error.find("would exceed"), std::string::npos) << error;
    EXPECT_NE(error.find("refusing to continue"), std::string::npos) << error;
    EXPECT_FALSE(fileExists(out)) << "the partial output is deleted";
    std::remove(in.c_str());
}

TEST(GzipLimits, ExpansionRatioOnlyAppliesAboveTheSizeFloor) {
    const auto in = writeBomb("bomb_ratio.gz", 2000);   // ~516 KB from ~3.3 KB: about 160:1
    const auto out = support::tempPath("bomb_ratio.out");
    std::string error;

    core::GunzipLimits limits;
    limits.maxOutput = 1ull << 30;
    limits.maxRatio = 50;
    limits.ratioFloor = 1ull << 30;   // never reached: a small file is fine however well it compresses
    EXPECT_TRUE(core::gunzipFile(in, out, error, nullptr, limits)) << error;
    std::remove(out.c_str());

    limits.ratioFloor = 100000;       // reached after ~100 KB
    EXPECT_FALSE(core::gunzipFile(in, out, error, nullptr, limits));
    EXPECT_NE(error.find("50:1"), std::string::npos) << error;
    EXPECT_NE(error.find("Refusing to continue"), std::string::npos) << error;
    EXPECT_FALSE(fileExists(out));

    limits.maxRatio = 1000;           // a ratio under the allowed maximum passes
    EXPECT_TRUE(core::gunzipFile(in, out, error, nullptr, limits)) << error;
    std::remove(out.c_str());
    std::remove(in.c_str());
}

TEST(GzipLimits, NormalFixturesPassWithTheDefaultLimits) {
    std::string content, error;
    ASSERT_TRUE(gunzip(kDir + "big.gz", content, error)) << error;
    EXPECT_GT(content.size(), 0u);
    const auto out = support::tempPath("limit_default.out");
    EXPECT_GT(core::defaultGunzipMaxOutput(out), 0u);
    EXPECT_LE(core::defaultGunzipMaxOutput(out), core::kGunzipMaxOutput);
}

TEST(GzipLimits, CancellationStillWinsOverTheLimits) {
    const auto in = writeBomb("bomb_cancel.gz", 1000);
    const auto out = support::tempPath("bomb_cancel.out");
    core::LoadControl control;
    control.cancelRequested = true;
    std::string error;
    core::GunzipLimits limits;
    limits.maxOutput = 100;
    EXPECT_FALSE(core::gunzipFile(in, out, error, &control, limits));
    EXPECT_TRUE(error.empty()) << "a cancel is not an error: " << error;
    std::remove(in.c_str());
    std::remove(out.c_str());
}

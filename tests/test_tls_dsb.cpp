// pcapng Decryption Secrets Blocks: reading them into the capture info and the key store, and writing them back on export.
// The block layout written by the exporter is checked against bytes laid out by Python's struct module.
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>

#include <core.h>
#include <export/export.h>
#include <tls/keylog.h>

#include "tls_support.h"

using namespace tlstest;
using support::put;

// ---- pcapng Decryption Secrets Blocks ---------------------------------------------------------------------

namespace {
    std::vector<char> block(bool be, uint32_t type, const std::vector<char> &body) {
        std::vector<char> b;
        const uint32_t total = 12 + static_cast<uint32_t>(body.size());
        put(b, type, be);
        put(b, total, be);
        b.insert(b.end(), body.begin(), body.end());
        put(b, total, be);
        return b;
    }
    void append(std::vector<char> &to, const std::vector<char> &b) { to.insert(to.end(), b.begin(), b.end()); }

    std::vector<char> shb(bool be) {
        std::vector<char> body;
        put<uint32_t>(body, 0x1A2B3C4D, be);
        put<uint16_t>(body, 1, be);
        put<uint16_t>(body, 0, be);
        put<int64_t>(body, -1, be);
        return block(be, 0x0A0D0D0A, body);
    }
    std::vector<char> idb(bool be) {
        std::vector<char> body;
        put<uint16_t>(body, 1, be);
        put<uint16_t>(body, 0, be);
        put<uint32_t>(body, 65535, be);
        return block(be, 1, body);
    }
    std::vector<char> epb(bool be) {
        const std::vector<char> frame = hex(support::kArpRequest);
        std::vector<char> body;
        put<uint32_t>(body, 0, be);
        put<uint32_t>(body, 0, be);
        put<uint32_t>(body, 1000, be);
        put<uint32_t>(body, static_cast<uint32_t>(frame.size()), be);
        put<uint32_t>(body, static_cast<uint32_t>(frame.size()), be);
        body.insert(body.end(), frame.begin(), frame.end());
        body.insert(body.end(), (4 - frame.size() % 4) % 4, 0);
        return block(be, 6, body);
    }
    // secrets type, secrets length (without padding), secrets, padding, optional options
    std::vector<char> dsb(bool be, uint32_t type, const std::string &secrets, bool withOption = false, uint32_t lengthField = 0xFFFFFFFF) {
        std::vector<char> body;
        put<uint32_t>(body, type, be);
        put<uint32_t>(body, lengthField == 0xFFFFFFFF ? static_cast<uint32_t>(secrets.size()) : lengthField, be);
        body.insert(body.end(), secrets.begin(), secrets.end());
        body.insert(body.end(), (4 - secrets.size() % 4) % 4, 0);
        if (withOption) {   // opt_comment "x" + opt_endofopt
            put<uint16_t>(body, 1, be); put<uint16_t>(body, 1, be); body.push_back('x'); body.insert(body.end(), 3, 0);
            put<uint32_t>(body, 0, be);
        }
        return block(be, 0x0A, body);
    }

    const std::string kLine1 = "CLIENT_RANDOM " + std::string(64, 'a') + " " + std::string(96, 'b');
    const std::string kLine2 = "CLIENT_TRAFFIC_SECRET_0 " + std::string(64, 'c') + " " + std::string(64, 'd');
}

TEST(TlsDsb, ReadInBothByteOrdersAndMergedIntoTheKeyStore) {
    for (bool be: {false, true}) {
        SCOPED_TRACE(be ? "big endian" : "little endian");
        std::vector<char> f;
        append(f, shb(be));
        append(f, idb(be));
        append(f, dsb(be, core::kSecretsTypeTlsKeyLog, kLine1 + "\n# comment\nbogus line here\n", true));   // padding (len % 4 != 0), options
        append(f, epb(be));
        append(f, dsb(be, core::kSecretsTypeTlsKeyLog, kLine2));                                          // after a packet: still read
        append(f, dsb(be, 0x57474b4c, "not a TLS key log"));                                               // another secrets type
        append(f, epb(be));
        Loaded cap(f, "dsb.pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;
        EXPECT_EQ(cap.packets.size(), 2u);
        const auto &info = cap.fp.captureInfo();
        ASSERT_EQ(info.decryptionSecrets.size(), 3u);
        EXPECT_EQ(info.decryptionSecrets[0].type, core::kSecretsTypeTlsKeyLog);
        EXPECT_EQ(info.decryptionSecrets[0].data, kLine1 + "\n# comment\nbogus line here\n") << "the raw text, padding removed";
        EXPECT_EQ(info.decryptionSecrets[2].type, 0x57474b4cu);
        EXPECT_EQ(info.tlsKeyLogSecrets, 2u);
        EXPECT_EQ(info.tlsKeyLogMalformed, 0u) << "an unknown label is not malformed";

        const auto &keys = cap.fp.sessions().tlsCaptureKeys();
        EXPECT_EQ(keys.entryCount(), 2u);
        EXPECT_EQ(keys.secretCount(), 2u);
        tls::ClientRandom a{}, c{};
        a.fill(0xaa);
        c.fill(0xcc);
        ASSERT_NE(keys.find(a), nullptr);
        EXPECT_EQ(keys.find(a)->get(tls::SecretKind::MasterSecret).hex(), std::string(96, 'b'));
        ASSERT_NE(keys.find(c), nullptr);
        EXPECT_TRUE(keys.find(c)->has(tls::SecretKind::ClientTraffic0));
        tls::KeyEntry merged;
        EXPECT_TRUE(cap.fp.sessions().findTlsKeys(a, merged));
        EXPECT_TRUE(merged.has(tls::SecretKind::MasterSecret));
        EXPECT_TRUE(cap.fp.sessions().tlsExternalKeys().empty());
    }
}

TEST(TlsDsb, BrokenBlocksAreIgnoredAndMalformedLinesCounted) {
    std::vector<char> f;
    append(f, shb(false));
    append(f, idb(false));
    append(f, dsb(false, core::kSecretsTypeTlsKeyLog, kLine1 + "\nCLIENT_RANDOM 12 34\n"));              // one bad line
    append(f, dsb(false, core::kSecretsTypeTlsKeyLog, kLine2, false, 4000));                            // length beyond the block
    append(f, block(false, 0x0A, std::vector<char>(4, 0)));                                              // too short for its header
    append(f, epb(false));
    Loaded cap(f, "dsb_broken.pcapng");
    ASSERT_TRUE(cap.ok) << cap.message;
    EXPECT_EQ(cap.packets.size(), 1u);
    const auto &info = cap.fp.captureInfo();
    EXPECT_EQ(info.decryptionSecrets.size(), 1u);
    EXPECT_EQ(info.tlsKeyLogSecrets, 1u);
    EXPECT_EQ(info.tlsKeyLogMalformed, 1u);
    EXPECT_EQ(cap.fp.sessions().tlsCaptureKeys().entryCount(), 1u);
}

TEST(TlsDsb, SecretsBeyondTheKeyStoreLimitAreReported) {
    std::string text;
    char line[256];
    for (size_t i = 0; i < tls::KeyStore::kMaxEntries + 3; ++i) {
        std::snprintf(line, sizeof line, "CLIENT_RANDOM %056x%08zx %s\n", 0, i, std::string(96, 'a').c_str());
        text += line;
    }
    std::vector<char> f;
    append(f, shb(false));
    append(f, idb(false));
    append(f, dsb(false, core::kSecretsTypeTlsKeyLog, text));
    append(f, epb(false));
    Loaded cap(f, "dsb_limit.pcapng");
    ASSERT_TRUE(cap.ok) << cap.message;
    EXPECT_EQ(cap.packets.size(), 1u);
    const auto &info = cap.fp.captureInfo();
    EXPECT_EQ(info.tlsKeyLogSecrets, tls::KeyStore::kMaxEntries);
    EXPECT_EQ(info.tlsKeyLogDropped, 3u);
    EXPECT_NE(cap.message.find("3 TLS secret(s) ignored: key store limit"), std::string::npos) << cap.message;
    EXPECT_EQ(cap.fp.sessions().tlsCaptureKeys().entryCount(), tls::KeyStore::kMaxEntries);
    EXPECT_TRUE(info.decryptionSecrets.empty()) << "a block over the 32 MiB retention cap is parsed but its text is not kept";
}

TEST(TlsDsb, CaptureKeysEndWithTheCaptureButUserKeysStay) {
    std::vector<char> f;
    append(f, shb(false));
    append(f, idb(false));
    append(f, dsb(false, core::kSecretsTypeTlsKeyLog, kLine1));
    append(f, epb(false));
    Loaded cap(f, "dsb_clear.pcapng");
    ASSERT_TRUE(cap.ok);
    cap.fp.sessions().tlsExternalKeys().parseText(kLine2);
    EXPECT_EQ(cap.fp.sessions().tlsCaptureKeys().entryCount(), 1u);

    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(cap.fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message)) << message;
    EXPECT_TRUE(cap.fp.sessions().tlsCaptureKeys().empty()) << "the next capture does not inherit the blocks of the previous one";
    EXPECT_EQ(cap.fp.sessions().tlsExternalKeys().entryCount(), 1u) << "keys the user supplied are kept";
    EXPECT_TRUE(cap.fp.captureInfo().decryptionSecrets.empty());
}

TEST(TlsDsb, ExportWritesTheBlocksBackAsPcapng) {
    // Python: struct.pack("<II", 0x0A, 196) + struct.pack("<II", 0x544c534b, 175) + text + b"\0" + struct.pack("<I", 196)
    const std::string text = "CLIENT_RANDOM " + std::string(64, '1') + " " + std::string(96, '2');
    ASSERT_EQ(text.size(), 175u);
    const std::string expectedBlock = raw("0a000000c4000000" "4b534c54af000000") + text + std::string(1, '\0') + raw("c4000000");
    ASSERT_EQ(expectedBlock.size(), 196u);

    const std::string sample = IMSHARK_TEST_DATA_DIR "/sample.pcap";
    std::vector<packet::PacketInfo> packets;
    core::FileProcessor fp;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(sample, packets, message)) << message;
    const std::vector<core::DecryptionSecrets> secrets = {{core::kSecretsTypeTlsKeyLog, text}};
    const std::string out = support::tempPath("dsb_export.pcapng");
    std::string error;
    ASSERT_TRUE(exporter::exportPackets(sample, packets, {0, 1}, fp.captureStartEpoch(), exporter::Format::Pcapng, out, error, nullptr, &secrets)) << error;
    const std::string bytes = slurp(out);
    EXPECT_NE(bytes.find(expectedBlock), std::string::npos) << "the block is laid out exactly as pcapng specifies";

    Loaded back(out);
    ASSERT_TRUE(back.ok) << back.message;
    EXPECT_EQ(back.packets.size(), 2u);
    ASSERT_EQ(back.fp.captureInfo().decryptionSecrets.size(), 1u);
    EXPECT_EQ(back.fp.captureInfo().decryptionSecrets[0].data, text);
    EXPECT_EQ(back.fp.captureInfo().tlsKeyLogSecrets, 1u);

    // without secrets the file carries none, and a classic pcap never does
    ASSERT_TRUE(exporter::exportPackets(sample, packets, {0}, fp.captureStartEpoch(), exporter::Format::Pcapng, out, error)) << error;
    Loaded plain(out);
    EXPECT_TRUE(plain.fp.captureInfo().decryptionSecrets.empty());
    ASSERT_TRUE(exporter::exportPackets(sample, packets, {0}, fp.captureStartEpoch(), exporter::Format::Pcap, out, error, nullptr, &secrets)) << error;
    EXPECT_EQ(slurp(out).find(text), std::string::npos);
    std::remove(out.c_str());
}

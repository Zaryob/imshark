// NSS key log parser (SSLKEYLOGFILE) and the key store the TLS decryptor looks secrets up in.
//
// Oracles: the fixtures in tests/data/tls hold key logs that OpenSSL 3 wrote during real handshakes, and
// tests/data/tls/expected.json (tools/make_tls_fixtures.py) names the client random and labels they must contain.
#include <gtest/gtest.h>

#include <tls/keylog.h>

#include "tls_support.h"

using namespace tlstest;

// ---- key log parser ---------------------------------------------------------------------------------------

TEST(TlsKeyLog, ValidLinesOfEveryLabel) {
    const std::string r = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";   // upper and lower case digits
    const std::string s48(96, 'a'), s32(64, 'b');
    const std::string text =
        "# SSL/TLS secrets log file\r\n"
        "\r\n"
        "CLIENT_RANDOM " + r + " " + s48 + "\r\n"
        "CLIENT_EARLY_TRAFFIC_SECRET " + r + " " + s32 + "\n"
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET\t" + r + "  " + s48 + "\n"
        "SERVER_HANDSHAKE_TRAFFIC_SECRET " + r + " " + s32 + "   \n"
        "CLIENT_TRAFFIC_SECRET_0 " + r + " " + s32 + "\n"
        "SERVER_TRAFFIC_SECRET_0 " + r + " " + s48 + "\n"
        "EXPORTER_SECRET " + r + " " + s32;                           // no line end after the last line
    tls::KeyStore store;
    const tls::KeyLogStats stats = store.parseText(text);
    EXPECT_EQ(stats.lines, 7u);
    EXPECT_EQ(stats.accepted, 7u);
    EXPECT_EQ(stats.malformed, 0u);
    EXPECT_EQ(stats.unknown, 0u);
    EXPECT_TRUE(stats.errors.empty());
    EXPECT_EQ(store.entryCount(), 1u);
    EXPECT_EQ(store.secretCount(), 7u);

    tls::ClientRandom key{};
    const auto bytes = hex(r);
    for (size_t i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(bytes[i]);
    const tls::KeyEntry *e = store.find(key);
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->get(tls::SecretKind::MasterSecret).length, 48u);
    EXPECT_EQ(e->get(tls::SecretKind::MasterSecret).hex(), s48);
    EXPECT_EQ(e->get(tls::SecretKind::ClientEarlyTraffic).length, 32u);
    EXPECT_EQ(e->get(tls::SecretKind::ClientHandshakeTraffic).length, 48u);
    EXPECT_EQ(e->get(tls::SecretKind::ServerHandshakeTraffic).hex(), s32);
    EXPECT_EQ(e->get(tls::SecretKind::ServerTraffic0).length, 48u);
    EXPECT_EQ(e->get(tls::SecretKind::Exporter).length, 32u);
    EXPECT_STREQ(tls::secretLabel(tls::SecretKind::ClientTraffic0), "CLIENT_TRAFFIC_SECRET_0");

    key[0] ^= 1;
    EXPECT_EQ(store.find(key), nullptr) << "lookup is by the whole client random";
}

TEST(TlsKeyLog, MalformedLinesAreCountedAndDoNotStopTheParse) {
    const std::string r(64, '1'), s48(96, '2'), s32(64, '3');
    const std::string text =
        "CLIENT_RANDOM " + r + " " + s48 + "\n"                                         // 1 ok
        "CLIENT_RANDOM " + r + "\n"                                                      // 2 missing secret
        "CLIENT_RANDOM " + r + " " + s48 + " extra\n"                                    // 3 extra field
        "CLIENT_RANDOM " + std::string(63, '1') + " " + s48 + "\n"                       // 4 random too short
        "CLIENT_RANDOM " + std::string(64, 'g') + " " + s48 + "\n"                       // 5 not hex
        "CLIENT_RANDOM " + r + " " + s32 + "\n"                                          // 6 master secret must be 48 bytes
        "CLIENT_TRAFFIC_SECRET_0 " + r + " " + std::string(65, '4') + "\n"               // 7 odd number of digits
        "SERVER_TRAFFIC_SECRET_0 " + r + " " + std::string(80, '4') + "\n"               // 8 40 bytes: neither 32 nor 48
        "EXPORTER_SECRET " + r + " " + std::string(95, 'z') + "x\n"                      // 9 bad digit
        "CLIENT_TRAFFIC_SECRET_1 " + r + " " + s32 + "\n"                                // 10 other label: unknown, ignored
        "# a comment\n"
        "   \n"
        "CLIENT_RANDOM " + std::string(5000, 'a') + "\n"                                 // 11 line too long
        "SERVER_HANDSHAKE_TRAFFIC_SECRET " + r + " " + s32 + "\n";                       // 12 ok
    tls::KeyStore store;
    const auto stats = store.parseText(text);
    EXPECT_EQ(stats.lines, 12u);
    EXPECT_EQ(stats.accepted, 2u);
    EXPECT_EQ(stats.malformed, 9u);
    EXPECT_EQ(stats.unknown, 1u);
    ASSERT_EQ(stats.errors.size(), 9u);
    EXPECT_EQ(stats.errors[0].rfind("line 2:", 0), 0u) << stats.errors[0];
    EXPECT_EQ(stats.errors[8].rfind("line 13:", 0), 0u) << "line numbers count blank and comment lines: " << stats.errors[8];
    EXPECT_EQ(store.secretCount(), 2u);
    EXPECT_EQ(store.entryCount(), 1u);
}

TEST(TlsKeyLog, LaterLinesReplaceAndStoresMerge) {
    const std::string r(64, '5');
    tls::KeyStore a, b;
    a.parseText("CLIENT_RANDOM " + r + " " + std::string(96, '1') + "\nEXPORTER_SECRET " + r + " " + std::string(64, '2') + "\n");
    a.parseText("CLIENT_RANDOM " + r + " " + std::string(96, '3') + "\n");
    tls::ClientRandom key{};
    key.fill(0x55);
    ASSERT_NE(a.find(key), nullptr);
    EXPECT_EQ(a.find(key)->get(tls::SecretKind::MasterSecret).hex(), std::string(96, '3'));
    EXPECT_EQ(a.secretCount(), 2u);

    b.parseText("CLIENT_TRAFFIC_SECRET_0 " + r + " " + std::string(64, '4') + "\nCLIENT_RANDOM " + std::string(64, '6') + " " + std::string(96, '7') + "\n");
    a.merge(b);
    EXPECT_EQ(a.entryCount(), 2u);
    EXPECT_EQ(a.find(key)->secretCount(), 3u);
    EXPECT_TRUE(a.find(key)->has(tls::SecretKind::ClientTraffic0));
    a.clear();
    EXPECT_TRUE(a.empty());
}

TEST(TlsKeyLog, StoreIsBounded) {
    std::string text;
    char line[200];
    for (size_t i = 0; i < tls::KeyStore::kMaxEntries + 3; ++i) {
        std::snprintf(line, sizeof line, "CLIENT_RANDOM %056x%08zx %s\n", 0, i, std::string(96, 'a').c_str());
        text += line;
    }
    tls::KeyStore store;
    const auto stats = store.parseText(text);
    EXPECT_EQ(stats.accepted, tls::KeyStore::kMaxEntries);
    EXPECT_EQ(stats.dropped, 3u);
    EXPECT_EQ(store.entryCount(), tls::KeyStore::kMaxEntries);
}

TEST(TlsKeyLog, AvailabilityDependsOnTheVersion) {
    tls::KeyStore store;
    const std::string r(64, '9');
    store.parseText("CLIENT_RANDOM " + r + " " + std::string(96, 'a') + "\n");
    tls::ClientRandom key{};
    key.fill(0x99);
    const tls::KeyEntry *e = store.find(key);
    EXPECT_EQ(tls::classify(e, 0x0303), tls::KeyAvailability::Tls12MasterSecret);
    EXPECT_EQ(tls::classify(e, 0), tls::KeyAvailability::Tls12MasterSecret);
    EXPECT_EQ(tls::classify(nullptr, 0x0303), tls::KeyAvailability::NotFound);
    EXPECT_STREQ(tls::availabilityText(tls::KeyAvailability::Tls12MasterSecret), "available (TLS 1.2 master secret)");
    EXPECT_STREQ(tls::availabilityText(tls::KeyAvailability::Tls13TrafficSecrets), "available (TLS 1.3 traffic secrets)");
    EXPECT_STREQ(tls::availabilityText(tls::KeyAvailability::NotFound), "not found");

    store.parseText("SERVER_TRAFFIC_SECRET_0 " + r + " " + std::string(64, 'b') + "\n");
    EXPECT_EQ(tls::classify(store.find(key), 0x0304), tls::KeyAvailability::Tls13TrafficSecrets);
    EXPECT_EQ(tls::classify(store.find(key), 0x0303), tls::KeyAvailability::Tls12MasterSecret);

    tls::KeyStore onlyExporter;
    onlyExporter.parseText("EXPORTER_SECRET " + r + " " + std::string(64, 'c') + "\nCLIENT_EARLY_TRAFFIC_SECRET " + r + " " + std::string(64, 'd') + "\n");
    EXPECT_EQ(tls::classify(onlyExporter.find(key), 0x0304), tls::KeyAvailability::NotFound) << "an exporter or early secret does not decrypt records";
}

TEST(TlsKeyLog, LoadsRealOpenSslKeyLogsFromFile) {
    for (const char *name: {"tls12", "tls13"}) {
        SCOPED_TRACE(name);
        const auto want = expected(name);
        tls::KeyStore store;
        tls::KeyLogStats stats;
        std::string error;
        ASSERT_TRUE(store.loadFile(kDir + name + ".keys", stats, error)) << error;
        EXPECT_EQ(stats.malformed, 0u);
        EXPECT_EQ(stats.unknown, 0u);
        EXPECT_EQ(stats.accepted, want.at("key_labels").items.size());
        ASSERT_EQ(store.entryCount(), 1u);
        const tls::ClientRandom random = randomOf(want.str("client_random"));
        const tls::KeyEntry *e = store.find(random.data());
        ASSERT_NE(e, nullptr);
        for (const auto &label: want.at("key_labels").items) {
            bool seen = false;
            for (size_t k = 0; k < tls::kSecretKinds; ++k) {
                if (label.text == tls::secretLabel(static_cast<tls::SecretKind>(k))) seen = e->secrets[k].present();
            }
            EXPECT_TRUE(seen) << label.text;
        }
    }
    tls::KeyStore store;
    tls::KeyLogStats stats;
    std::string error;
    EXPECT_FALSE(store.loadFile(kDir + "no-such.keys", stats, error));
    EXPECT_FALSE(error.empty());
    EXPECT_EQ(stats.lines, 0u);
}

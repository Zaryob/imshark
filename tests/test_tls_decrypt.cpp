// TLS record decryptor (tls/record_decryptor.h): key derivation, nonce / AAD construction, key epochs and status codes.
//
// Oracles (nothing is computed by the code under test):
//   - RFC 8448 section 3 "Simple 1-RTT Handshake": the traffic secrets, and the records whose plaintext the RFC specifies
//     (the client Finished with verify_data a8ec436d..., and the 50 byte application data 00..31 of each direction)
//     sealed with the RFC's keys and IVs by an independent implementation (Node's crypto, see the generator below).
//     The RFC text itself is not available offline here; the secrets, keys, IVs and verify_data are the RFC's published
//     values (reproduced by the key schedule test of test_tls_crypto.cpp), the record bytes follow from them.
//   - tests/data/tls/decrypt_tls13.json and decrypt_tls12.json (tools/make_tls_fixtures.py --decrypt): real connections of
//     `openssl s_client` and `openssl s_server`, one per supported cipher suite; the plaintext they must decrypt to is
//     what the client sent and what s_client printed after OpenSSL decrypted the response, the secrets are the key log
//     OpenSSL wrote (including OpenSSL's own traffic_secret_N+1 after a KeyUpdate).
//
// The "sealed" constants below were produced with this Node snippet (aes-128-gcm, key/iv = HKDF-Expand-Label of the
// secret, nonce = iv XOR seq, AAD = record header, inner plaintext = content || type || zero padding):
//   function seal(secret, seq, type, content, pad = 0, ver = 0x0303) { const key = expandLabel(secret, 'key', E, 16),
//     iv = expandLabel(secret, 'iv', E, 12); const nonce = Buffer.from(iv); let s = BigInt(seq);
//     for (let i = 11; i >= 4; i--) { nonce[i] ^= Number(s & 0xffn); s >>= 8n; }
//     const inner = Buffer.concat([content, Buffer.from([type]), Buffer.alloc(pad)]);
//     const hdr = Buffer.from([0x17, ver >> 8, ver & 255, 0, 0]); hdr.writeUInt16BE(inner.length + 16, 3);
//     const x = crypto.createCipheriv('aes-128-gcm', key, nonce, {authTagLength: 16}); x.setAAD(hdr);
//     return Buffer.concat([hdr, x.update(inner), x.final(), x.getAuthTag()]).subarray(5).toString('hex'); }
#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tls/crypto.h>
#include <tls/keylog.h>
#include <tls/record_decryptor.h>

#include "tls_support.h"

namespace {
    using tls::DecryptStatus;
    using tls::Direction;
    using tls::KeyEpoch;
    using tls::crypto::Bytes;

    Bytes bytesOf(const std::string &hexText) {
        Bytes out;
        for (char c: support::hex(hexText)) out.push_back(static_cast<uint8_t>(c));
        return out;
    }

    std::string hexOf(const Bytes &b) { return support::hexOf(std::string(b.begin(), b.end())); }

    const std::string kClientRandomHex(64, '1');    // the random only selects the key log entry for TLS 1.3
    tls::ClientRandom randomA() { return tlstest::randomOf(kClientRandomHex); }
    tls::ClientRandom randomB() { return tlstest::randomOf(std::string(64, '2')); }

    // a key store entry built from key log text, like the load pass does it
    struct Keys {
        tls::KeyStore store;
        explicit Keys(const std::string &lines) {
            const auto stats = store.parseText(lines);
            EXPECT_EQ(stats.malformed, 0u);
        }
        const tls::KeyEntry *entry() const { return store.find(randomA()); }
    };

    std::string logLine(const char *label, const std::string &secretHex) { return std::string(label) + " " + kClientRandomHex + " " + secretHex + "\n"; }

    // RFC 8448 section 3 secrets
    const std::string kClientHs = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const std::string kServerHs = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const std::string kClientAp = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const std::string kServerAp = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";

    std::string rfc8448Log() {
        return logLine("CLIENT_HANDSHAKE_TRAFFIC_SECRET", kClientHs) + logLine("SERVER_HANDSHAKE_TRAFFIC_SECRET", kServerHs) +
               logLine("CLIENT_TRAFFIC_SECRET_0", kClientAp) + logLine("SERVER_TRAFFIC_SECRET_0", kServerAp);
    }

    tls::DecryptedRecord open(tls::RecordDecryptor &dec, Direction d, const std::string &fragmentHex, uint8_t type = 23, uint16_t version = 0x0303) {
        const Bytes fragment = bytesOf(fragmentHex);
        return dec.decrypt(d, type, version, fragment);
    }

    // RFC 8448 records (fragment = the bytes after the 5 byte header)
    const std::string kClientFinishedRecord =   // {client} Finished under the client handshake keys, sequence 0
        "75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546";
    const std::string kClientApplicationRecord =   // 50 bytes 00..31 under the client application keys, sequence 0
        "a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4";
    const std::string kServerApplicationRecord =   // 50 bytes 00..31 under the server application keys, sequence 0
        "3e6a8d5a454f91cf674394496600eb1ce8163540fa79e3e8297b6148bfe5e8aaa0dbfb96ad9aa912df8b84e146979bbf7e4059a5177ad560f2cfe674b7650561229589";

    Bytes zeroToFortyNine() {
        Bytes b;
        for (int i = 0; i < 50; ++i) b.push_back(static_cast<uint8_t>(i));
        return b;
    }

    // ---- fixture cases ------------------------------------------------------------------------------------------

    struct Rec {
        uint8_t type;
        uint16_t version;
        Bytes fragment;
    };

    struct Case {
        std::string name, keylog;
        uint16_t version, cipher;
        tls::ClientRandom clientRandom, serverRandom;
        std::vector<Rec> records[2];   // indexed by Direction
        Bytes application[2];          // expected application_data of each direction
        std::string updateSecret[2];   // TLS 1.3: OpenSSL's traffic_secret_N+1 of each direction (hex), empty for TLS 1.2
    };

    std::vector<Case> loadCases(const std::string &file) {
        std::vector<Case> out;
        const auto doc = testutil::JsonParser(tlstest::slurp(tlstest::kDir + file)).parse();
        for (const auto &j: doc.at("cases").items) {
            Case c;
            c.name = j.str("name");
            c.keylog = j.str("keylog");
            c.version = static_cast<uint16_t>(j.num("version"));
            c.cipher = static_cast<uint16_t>(j.num("cipher"));
            c.clientRandom = tlstest::randomOf(j.str("client_random"));
            c.serverRandom = tlstest::randomOf(j.str("server_random"));
            const char *names[2] = {"c2s", "s2c"};
            for (int d = 0; d < 2; ++d) {
                for (const auto &r: j.at(names[d]).items) {
                    c.records[d].push_back({static_cast<uint8_t>(r.num("type")), static_cast<uint16_t>(r.num("version")), bytesOf(r.str("fragment"))});
                }
            }
            c.application[0] = bytesOf(j.str("c2s_application_data"));
            c.application[1] = bytesOf(j.str("s2c_application_data"));
            if (j.has("update_secrets")) {
                c.updateSecret[0] = j.at("update_secrets").str("c2s");
                c.updateSecret[1] = j.at("update_secrets").str("s2c");
            }
            out.push_back(std::move(c));
        }
        return out;
    }

    struct Prepared {
        tls::KeyStore store;
        tls::RecordDecryptor dec;
        explicit Prepared(const Case &c, const std::string &logOverride = "")
            : store(), dec(c.version, c.cipher, c.clientRandom, c.serverRandom, (parse(c, logOverride), store.find(c.clientRandom))) {}
        void parse(const Case &c, const std::string &logOverride) { store.parseText(logOverride.empty() ? c.keylog : logOverride); }
    };

    // decrypts every record of one direction in order; returns the application data and the statuses
    struct DirRun {
        Bytes application;
        std::vector<DecryptStatus> status;
        std::vector<tls::DecryptedRecord> records;
    };

    DirRun runDirection(tls::RecordDecryptor &dec, const Case &c, Direction d) {
        DirRun run;
        for (const Rec &r: c.records[static_cast<size_t>(d)]) {
            auto result = dec.decrypt(d, r.type, r.version, r.fragment);
            run.status.push_back(result.status);
            if (result.status == DecryptStatus::Decrypted && result.contentType == 23) {
                run.application.insert(run.application.end(), result.plaintext.begin(), result.plaintext.end());
            }
            run.records.push_back(std::move(result));
        }
        return run;
    }

    class TlsDecrypt : public ::testing::Test {
    protected:
        void SetUp() override {
            if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
        }
    };
}

// ---- cipher suite table -----------------------------------------------------------------------------------------

TEST(TlsDecryptSuites, Tls13SuitesAreSupportedAndOthersAreNot) {
    ASSERT_NE(tls::findCipherSuite(0x0304, 0x1301), nullptr);
    EXPECT_STREQ(tls::findCipherSuite(0x0304, 0x1301)->name, "TLS_AES_128_GCM_SHA256");
    ASSERT_NE(tls::findCipherSuite(0x0304, 0x1302), nullptr);
    EXPECT_EQ(tls::findCipherSuite(0x0304, 0x1302)->hash, tls::crypto::Hash::Sha384);
    ASSERT_NE(tls::findCipherSuite(0x0304, 0x1303), nullptr);
    EXPECT_EQ(tls::findCipherSuite(0x0304, 0x1303)->aead, tls::crypto::Aead::ChaCha20Poly1305);
    EXPECT_EQ(tls::findCipherSuite(0x0304, 0x1304), nullptr);   // TLS_AES_128_CCM_SHA256
    EXPECT_EQ(tls::findCipherSuite(0x0304, 0x1305), nullptr);   // TLS_AES_128_CCM_8_SHA256
    EXPECT_EQ(tls::findCipherSuite(0x0304, 0x002f), nullptr);   // TLS_RSA_WITH_AES_128_CBC_SHA
    EXPECT_EQ(tls::findCipherSuite(0x0301, 0x1301), nullptr);   // a TLS 1.3 suite under an older version
    EXPECT_EQ(tls::findCipherSuite(0, 0x1301), nullptr);
}

TEST(TlsDecryptSuites, StatusTexts) {
    EXPECT_STREQ(tls::decryptStatusText(DecryptStatus::Decrypted), "decrypted");
    EXPECT_STREQ(tls::decryptStatusText(DecryptStatus::TagFailure), "tag failure (wrong key?)");
    EXPECT_STREQ(tls::decryptStatusText(DecryptStatus::NoKey), "no key");
    EXPECT_STREQ(tls::decryptStatusText(DecryptStatus::UnsupportedSuite), "unsupported cipher suite");
}

// ---- RFC 8448 ---------------------------------------------------------------------------------------------------

TEST_F(TlsDecrypt, Rfc8448ClientFinishedAndApplicationData) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(dec.availability(), DecryptStatus::Decrypted);

    auto finished = open(dec, Direction::ClientToServer, kClientFinishedRecord);
    ASSERT_EQ(finished.status, DecryptStatus::Decrypted);
    EXPECT_EQ(finished.contentType, 22);
    EXPECT_EQ(hexOf(finished.plaintext), "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");   // RFC 8448 verify_data
    EXPECT_EQ(finished.sequence, 0u);
    EXPECT_EQ(finished.epoch, KeyEpoch::Handshake);
    EXPECT_EQ(dec.epoch(Direction::ClientToServer), KeyEpoch::Application);   // Finished sent: application keys from now on
    EXPECT_EQ(dec.sequence(Direction::ClientToServer), 0u);

    auto data = open(dec, Direction::ClientToServer, kClientApplicationRecord);
    ASSERT_EQ(data.status, DecryptStatus::Decrypted);
    EXPECT_EQ(data.contentType, 23);
    EXPECT_EQ(data.plaintext, zeroToFortyNine());
    EXPECT_EQ(data.epoch, KeyEpoch::Application);
    EXPECT_EQ(dec.sequence(Direction::ClientToServer), 1u);
}

TEST_F(TlsDecrypt, Rfc8448ServerApplicationDataReachedByTheFirstApplicationKey) {
    // the server's handshake records are not in the input: its first record fails under the handshake keys and the first
    // application key opens it
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    auto data = open(dec, Direction::ServerToClient, kServerApplicationRecord);
    ASSERT_EQ(data.status, DecryptStatus::Decrypted);
    EXPECT_EQ(data.plaintext, zeroToFortyNine());
    EXPECT_EQ(data.epoch, KeyEpoch::Application);
    EXPECT_EQ(data.sequence, 0u);
    EXPECT_EQ(dec.epoch(Direction::ServerToClient), KeyEpoch::Application);
}

TEST_F(TlsDecrypt, Rfc8448OnlyApplicationSecretsKnown) {
    Keys keys(logLine("CLIENT_TRAFFIC_SECRET_0", kClientAp) + logLine("SERVER_TRAFFIC_SECRET_0", kServerAp));
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(dec.availability(), DecryptStatus::Decrypted);
    // the handshake record cannot be opened without its secret
    EXPECT_EQ(open(dec, Direction::ClientToServer, kClientFinishedRecord).status, DecryptStatus::NoKey);
    EXPECT_EQ(dec.sequence(Direction::ClientToServer), 0u);       // not tried, not counted
    auto data = open(dec, Direction::ClientToServer, kClientApplicationRecord);
    ASSERT_EQ(data.status, DecryptStatus::Decrypted);
    EXPECT_EQ(data.plaintext, zeroToFortyNine());
}

TEST_F(TlsDecrypt, WrongDirectionOrReplayedRecordFailsTheTag) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(open(dec, Direction::ServerToClient, kClientApplicationRecord).status, DecryptStatus::TagFailure);   // client record, server keys
    tls::RecordDecryptor again(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    ASSERT_EQ(open(again, Direction::ClientToServer, kClientFinishedRecord).status, DecryptStatus::Decrypted);
    ASSERT_EQ(open(again, Direction::ClientToServer, kClientApplicationRecord).status, DecryptStatus::Decrypted);
    auto replay = open(again, Direction::ClientToServer, kClientApplicationRecord);   // sequence number 1 now
    EXPECT_EQ(replay.status, DecryptStatus::TagFailure);
    EXPECT_TRUE(replay.plaintext.empty());
}

// ---- nonce, AAD, padding, epochs (records sealed with the RFC 8448 server application secret) -------------------

TEST_F(TlsDecrypt, NonceUsesTheFull64BitSequenceNumber) {
    // get the server into the application epoch first, then jump the sequence number
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    ASSERT_EQ(open(dec, Direction::ServerToClient, kServerApplicationRecord).status, DecryptStatus::Decrypted);
    const std::string sealed = "68f7ee0636a28bc7f8eb65c6f9230447bee0354b4f0b18097ab9c6510a221b9a17ddcf1069";   // sequence 0x0102030405060708
    dec.setSequence(Direction::ServerToClient, 0x0102030405060707ull);   // one too low: the nonce differs in the lowest byte
    EXPECT_EQ(open(dec, Direction::ServerToClient, sealed).status, DecryptStatus::TagFailure);
    dec.setSequence(Direction::ServerToClient, 0x0102030405060708ull);
    auto r = open(dec, Direction::ServerToClient, sealed);
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    EXPECT_EQ(std::string(r.plaintext.begin(), r.plaintext.end()), "sequence number test");
    EXPECT_EQ(r.sequence, 0x0102030405060708ull);
    EXPECT_EQ(dec.sequence(Direction::ServerToClient), 0x0102030405060709ull);
}

TEST_F(TlsDecrypt, AdditionalDataIsTheRecordHeader) {
    Keys keys(rfc8448Log());
    const std::string sealed = "480efd2a2825f9e80624be2a0f6c81768a1040e8cdb423bcdc1bad3dfa01eb8be8fa";   // sealed with record version 0x0301 in the header
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(open(dec, Direction::ServerToClient, sealed, 23, 0x0303).status, DecryptStatus::TagFailure);   // header says 0x0303
    tls::RecordDecryptor ok(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(open(ok, Direction::ServerToClient, sealed, 23, 0x0301).status, DecryptStatus::Decrypted);
}

TEST_F(TlsDecrypt, InnerContentTypeAndPaddingAreStripped) {
    Keys keys(rfc8448Log());
    auto fresh = [&] { return tls::RecordDecryptor(0x0304, 0x1301, randomA(), randomB(), keys.entry()); };
    {
        auto dec = fresh();
        auto r = open(dec, Direction::ServerToClient, "4e0aeb3d242e80c86f4a9e426a0de4bf280399ebf95e7655c1314ba6d626");   // "padded" + type 23 + 7 zero bytes
        ASSERT_EQ(r.status, DecryptStatus::Decrypted);
        EXPECT_EQ(std::string(r.plaintext.begin(), r.plaintext.end()), "padded");
        EXPECT_EQ(r.contentType, 23);
    }
    {
        auto dec = fresh();   // empty content: the inner plaintext is just the type byte
        auto r = open(dec, Direction::ServerToClient, "292e9d47d3beec9aec58466d05f7718a2c");
        ASSERT_EQ(r.status, DecryptStatus::Decrypted);
        EXPECT_TRUE(r.plaintext.empty());
        EXPECT_EQ(r.contentType, 23);
    }
    {
        auto dec = fresh();   // authenticated but all zero: no content type at all
        auto r = open(dec, Direction::ServerToClient, "3e6b8f59414a97c86f4a9e426a0de513f8072753ee7d3f1d3e2d92ce30c2cb97098eef70");
        EXPECT_EQ(r.status, DecryptStatus::Malformed);
        EXPECT_TRUE(r.plaintext.empty());
        EXPECT_EQ(dec.sequence(Direction::ServerToClient), 1u);   // the record was authentic, so it used its sequence number
    }
}

TEST_F(TlsDecrypt, HandshakeToApplicationKeysAfterAFinishedThatSpansRecords) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    // record 0: EncryptedExtensions (RFC 8448) + the first two header bytes of Finished; record 1: the rest of Finished
    auto r0 = open(dec, Direction::ServerToClient,
                   "d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f857a7dd308e9e784a2be1a44d408de6c6e84c8e");
    ASSERT_EQ(r0.status, DecryptStatus::Decrypted);
    EXPECT_EQ(r0.contentType, 22);
    EXPECT_EQ(r0.plaintext.size(), 42u);
    EXPECT_EQ(r0.epoch, KeyEpoch::Handshake);
    EXPECT_EQ(dec.epoch(Direction::ServerToClient), KeyEpoch::Handshake);   // only half of the Finished header is here
    auto r1 = open(dec, Direction::ServerToClient, "7d26a3ad20c69bead1e320699a030231af0c880571ec414b664d19f95d954f0a0952d63ec7a692048cae89a080942b7de9492e");
    ASSERT_EQ(r1.status, DecryptStatus::Decrypted);
    EXPECT_EQ(r1.sequence, 1u);
    EXPECT_EQ(r1.epoch, KeyEpoch::Handshake);
    EXPECT_EQ(dec.epoch(Direction::ServerToClient), KeyEpoch::Application);
    EXPECT_EQ(dec.epoch(Direction::ClientToServer), KeyEpoch::Handshake);   // directions switch independently
    auto r2 = open(dec, Direction::ServerToClient, "4d0efd2f2438b7ac0e3eff620b6b91768a27613a8005869754066c27ba420f43c4670e907b7826f758f272");
    ASSERT_EQ(r2.status, DecryptStatus::Decrypted);
    EXPECT_EQ(std::string(r2.plaintext.begin(), r2.plaintext.end()), "server data after Finished");
    EXPECT_EQ(r2.epoch, KeyEpoch::Application);
    EXPECT_EQ(r2.sequence, 0u);   // the sequence number restarts with the new keys
}

TEST_F(TlsDecrypt, KeyUpdateMovesToTheNextTrafficSecretEachTime) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    const Direction s = Direction::ServerToClient;
    auto r = open(dec, s, "5c0ee936332fb7bd1f2eff360f1afbf0838a642dac729ea9cd0918982a2b");      // generation 0, sequence 0 (first key rule)
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    EXPECT_EQ(r.keyUpdates, 0u);
    r = open(dec, s, "36927c13eb599842ddbfc0578d1d1cddb9f336255b23");                           // generation 0, sequence 1: carries a KeyUpdate
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    EXPECT_EQ(r.contentType, 22);
    EXPECT_EQ(hexOf(r.plaintext), "1800000100");
    r = open(dec, s, "10cf6a3ff7daa0cc5778dd5222f1bef50d65890c4370735df2baa73208475a");         // generation 1 (traffic_secret_N+1), sequence 0
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    EXPECT_EQ(std::string(r.plaintext.begin(), r.plaintext.end()), "generation one");
    EXPECT_EQ(r.keyUpdates, 1u);
    EXPECT_EQ(r.sequence, 0u);
    r = open(dec, s, "97b8a959cfc3212558abb7cff3ed429c82dfc528ce1f");                           // generation 1, sequence 1: another KeyUpdate
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    r = open(dec, s, "7e85814914adffc1c0b931ced36f316215808bbfa0f91b742240e25fc4bc43");         // generation 2
    ASSERT_EQ(r.status, DecryptStatus::Decrypted);
    EXPECT_EQ(std::string(r.plaintext.begin(), r.plaintext.end()), "generation two");
    EXPECT_EQ(r.keyUpdates, 2u);
    EXPECT_EQ(dec.epoch(s), KeyEpoch::Application);
}

TEST_F(TlsDecrypt, KeyUpdateOfOneDirectionLeavesTheOtherAlone) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    ASSERT_EQ(open(dec, Direction::ServerToClient, "5c0ee936332fb7bd1f2eff360f1afbf0838a642dac729ea9cd0918982a2b").status, DecryptStatus::Decrypted);
    ASSERT_EQ(open(dec, Direction::ServerToClient, "36927c13eb599842ddbfc0578d1d1cddb9f336255b23").status, DecryptStatus::Decrypted);
    auto client = open(dec, Direction::ClientToServer, kClientFinishedRecord);   // still generation 0 / handshake keys
    ASSERT_EQ(client.status, DecryptStatus::Decrypted);
    EXPECT_EQ(client.keyUpdates, 0u);
}

// ---- statuses ---------------------------------------------------------------------------------------------------

TEST_F(TlsDecrypt, UnsupportedSuiteIsReportedBeforeKeysAreLookedAt) {
    Keys keys(rfc8448Log());
    for (uint16_t suite: {0x1304, 0x1305, 0x002f, 0x0000}) {
        tls::RecordDecryptor dec(0x0304, suite, randomA(), randomB(), keys.entry());
        EXPECT_EQ(dec.availability(), DecryptStatus::UnsupportedSuite) << suite;
        auto r = open(dec, Direction::ClientToServer, kClientApplicationRecord);
        EXPECT_EQ(r.status, DecryptStatus::UnsupportedSuite);
        EXPECT_TRUE(r.plaintext.empty());
    }
    tls::RecordDecryptor oldVersion(0x0302, 0x1301, randomA(), randomB(), keys.entry());   // TLS 1.1 with a TLS 1.3 suite id
    EXPECT_EQ(open(oldVersion, Direction::ClientToServer, kClientApplicationRecord).status, DecryptStatus::UnsupportedSuite);
}

TEST_F(TlsDecrypt, NoKeyWhenTheStoreHasNothingUsable) {
    {   // no entry at all
        tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), nullptr);
        EXPECT_EQ(dec.availability(), DecryptStatus::NoKey);
        EXPECT_EQ(open(dec, Direction::ClientToServer, kClientApplicationRecord).status, DecryptStatus::NoKey);
    }
    {   // only an exporter secret and a TLS 1.2 style master secret
        Keys keys(logLine("EXPORTER_SECRET", kClientAp) + "CLIENT_RANDOM " + kClientRandomHex + " " + std::string(96, 'a') + "\n");
        tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
        EXPECT_EQ(dec.availability(), DecryptStatus::NoKey);
        EXPECT_EQ(open(dec, Direction::ServerToClient, kServerApplicationRecord).status, DecryptStatus::NoKey);
    }
    {   // 32 byte secrets with a SHA-384 suite do not fit the suite
        Keys keys(rfc8448Log());
        tls::RecordDecryptor dec(0x0304, 0x1302, randomA(), randomB(), keys.entry());
        EXPECT_EQ(dec.availability(), DecryptStatus::NoKey);
        EXPECT_EQ(open(dec, Direction::ClientToServer, kClientFinishedRecord).status, DecryptStatus::NoKey);
    }
    {   // one direction known, the other not
        Keys keys(logLine("CLIENT_HANDSHAKE_TRAFFIC_SECRET", kClientHs));
        tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
        EXPECT_EQ(dec.availability(), DecryptStatus::Decrypted);
        EXPECT_EQ(open(dec, Direction::ServerToClient, kServerApplicationRecord).status, DecryptStatus::NoKey);
        EXPECT_EQ(open(dec, Direction::ClientToServer, kClientFinishedRecord).status, DecryptStatus::Decrypted);
        EXPECT_EQ(open(dec, Direction::ClientToServer, kClientApplicationRecord).status, DecryptStatus::NoKey);   // no application secret
    }
}

TEST_F(TlsDecrypt, WrongSecretIsATagFailureNotGarbage) {
    std::string wrong = kClientHs;
    wrong[10] = wrong[10] == '0' ? '1' : '0';
    Keys keys(logLine("CLIENT_HANDSHAKE_TRAFFIC_SECRET", wrong));
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    auto r = open(dec, Direction::ClientToServer, kClientFinishedRecord);
    EXPECT_EQ(r.status, DecryptStatus::TagFailure);
    EXPECT_TRUE(r.plaintext.empty());
    EXPECT_EQ(dec.epoch(Direction::ClientToServer), KeyEpoch::Handshake);
}

TEST_F(TlsDecrypt, RecordsThatCannotBeProtectedRecordsAreMalformed) {
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    const Bytes good = bytesOf(kClientFinishedRecord);
    EXPECT_EQ(dec.decrypt(Direction::ClientToServer, 22, 0x0303, good).status, DecryptStatus::Malformed);          // plaintext handshake record
    EXPECT_EQ(dec.decrypt(Direction::ClientToServer, 23, 0x0303, {}).status, DecryptStatus::Malformed);
    EXPECT_EQ(dec.decrypt(Direction::ClientToServer, 23, 0x0303, std::span<const uint8_t>(good).first(16)).status, DecryptStatus::Malformed);   // tag only
    EXPECT_EQ(dec.decrypt(Direction::ClientToServer, 23, 0x0303, Bytes(16384 + 256 + 1, 0)).status, DecryptStatus::Malformed);
    EXPECT_EQ(dec.sequence(Direction::ClientToServer), 0u);   // none of them used a sequence number
    EXPECT_EQ(dec.decrypt(Direction::ClientToServer, 23, 0x0303, good).status, DecryptStatus::Decrypted);
}

TEST_F(TlsDecrypt, EveryDamagedOrCutRecordIsRejected) {
    Keys keys(rfc8448Log());
    const Bytes good = bytesOf(kClientApplicationRecord);
    auto fresh = [&] {
        auto dec = std::make_unique<tls::RecordDecryptor>(0x0304, 0x1301, randomA(), randomB(), keys.entry());
        EXPECT_EQ(open(*dec, Direction::ClientToServer, kClientFinishedRecord).status, DecryptStatus::Decrypted);
        return dec;
    };
    for (size_t i = 0; i < good.size(); ++i) {   // a flipped bit in any byte fails the tag
        for (int bit = 0; bit < 8; bit += 7) {
            Bytes bad = good;
            bad[i] ^= static_cast<uint8_t>(1 << bit);
            auto r = fresh()->decrypt(Direction::ClientToServer, 23, 0x0303, bad);
            EXPECT_EQ(r.status, DecryptStatus::TagFailure) << i;
            EXPECT_TRUE(r.plaintext.empty());
        }
    }
    for (size_t len = 0; len < good.size(); ++len) {   // every truncation is Malformed or TagFailure
        auto r = fresh()->decrypt(Direction::ClientToServer, 23, 0x0303, std::span<const uint8_t>(good).first(len));
        EXPECT_TRUE(r.status == DecryptStatus::Malformed || r.status == DecryptStatus::TagFailure) << len;
        EXPECT_TRUE(r.plaintext.empty());
    }
}

// ---- real connections of OpenSSL, one per supported TLS 1.3 suite ---------------------------------------------------

TEST_F(TlsDecrypt, OpenSslTls13ConnectionsDecryptToTheKnownPlaintext) {
    const auto cases = loadCases("decrypt_tls13.json");
    ASSERT_EQ(cases.size(), 3u);
    for (const Case &c: cases) {
        SCOPED_TRACE(c.name);
        Prepared p(c);
        ASSERT_EQ(p.dec.availability(), DecryptStatus::Decrypted);
        const size_t finishedSize = 4 + (c.cipher == 0x1302 ? 48 : 32);
        for (Direction d: {Direction::ClientToServer, Direction::ServerToClient}) {
            const DirRun run = runDirection(p.dec, c, d);
            for (size_t i = 0; i < run.status.size(); ++i) EXPECT_EQ(run.status[i], DecryptStatus::Decrypted) << "record " << i;
            EXPECT_EQ(run.application, c.application[static_cast<size_t>(d)]);
            // the handshake epoch ends with that direction's Finished (the last message of its last record); the KeyUpdate
            // OpenSSL sent comes before the data
            bool sawFinished = false;
            uint32_t lastUpdates = 0;
            for (const auto &r: run.records) {
                if (r.contentType == 22 && r.epoch == KeyEpoch::Handshake) {
                    EXPECT_FALSE(sawFinished);
                    sawFinished = r.plaintext.size() >= finishedSize && r.plaintext[r.plaintext.size() - finishedSize] == 20;
                }
                if (r.contentType == 23) EXPECT_EQ(r.epoch, KeyEpoch::Application);
                lastUpdates = r.keyUpdates;
            }
            EXPECT_TRUE(sawFinished);
            EXPECT_EQ(lastUpdates, 1u) << "the data follows the KeyUpdate of its direction";
            EXPECT_EQ(p.dec.epoch(d), KeyEpoch::Application);
        }
    }
}

TEST_F(TlsDecrypt, OpenSslKeyUpdateSecretsEqualTheDerivedNextSecret) {
    // OpenSSL logs the updated secrets; they must equal HKDF-Expand-Label(secret_0, "traffic upd", "", HashLen)
    for (const Case &c: loadCases("decrypt_tls13.json")) {
        SCOPED_TRACE(c.name);
        tls::KeyStore store;
        store.parseText(c.keylog);
        const tls::KeyEntry *e = store.find(c.clientRandom);
        ASSERT_NE(e, nullptr);
        const auto hash = c.cipher == 0x1302 ? tls::crypto::Hash::Sha384 : tls::crypto::Hash::Sha256;
        const tls::Secret *secrets[2] = {&e->get(tls::SecretKind::ClientTraffic0), &e->get(tls::SecretKind::ServerTraffic0)};
        for (int d = 0; d < 2; ++d) {
            const auto next = tls::crypto::hkdfExpandLabel(hash, std::span<const uint8_t>(secrets[d]->bytes.data(), secrets[d]->length), "traffic upd",
                                                           {}, tls::crypto::hashLength(hash));
            ASSERT_TRUE(next.has_value());
            EXPECT_EQ(hexOf(*next), c.updateSecret[d]);
        }
    }
}

TEST_F(TlsDecrypt, OpenSslTls13RecordsWithTheKeysOfAnotherConnectionFailTheTag) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &a = cases[0], &b = cases[2];                 // both SHA-256: the secrets have the right size for a's suite
    std::string text = b.keylog;                             // b's key log, filed under a's client random
    const std::string bRandom = tlstest::hexOfRandom(b.clientRandom), aRandom = tlstest::hexOfRandom(a.clientRandom);
    for (size_t at; (at = text.find(bRandom)) != std::string::npos;) text.replace(at, bRandom.size(), aRandom);
    Prepared p(a, text);
    for (Direction d: {Direction::ClientToServer, Direction::ServerToClient}) {
        const DirRun run = runDirection(p.dec, a, d);
        for (auto status: run.status) EXPECT_EQ(status, DecryptStatus::TagFailure);
        EXPECT_TRUE(run.application.empty());
    }
}

TEST_F(TlsDecrypt, OpenSslTls13WithoutHandshakeSecretsStillOpensTheApplicationData) {
    for (const Case &c: loadCases("decrypt_tls13.json")) {
        SCOPED_TRACE(c.name);
        std::string kept;
        for (size_t pos = 0; pos < c.keylog.size();) {
            const size_t end = c.keylog.find('\n', pos);
            const std::string line = c.keylog.substr(pos, end == std::string::npos ? std::string::npos : end - pos + 1);
            if (line.find("HANDSHAKE") == std::string::npos) kept += line;
            if (end == std::string::npos) break;
            pos = end + 1;
        }
        Prepared p(c, kept);
        const DirRun run = runDirection(p.dec, c, Direction::ServerToClient);
        EXPECT_EQ(run.application, c.application[1]);
        EXPECT_EQ(run.status.front(), DecryptStatus::NoKey);   // the handshake records have no secret
    }
}

// ---- TLS 1.2 ----------------------------------------------------------------------------------------------------

TEST(TlsDecryptSuites, Tls12AeadSuitesAreSupportedAndOthersAreNot) {
    struct Expect {
        uint16_t id;
        tls::crypto::Aead aead;
        tls::crypto::Hash hash;
    };
    const Expect supported[] = {
        {0x009C, tls::crypto::Aead::Aes128Gcm, tls::crypto::Hash::Sha256}, {0x009D, tls::crypto::Aead::Aes256Gcm, tls::crypto::Hash::Sha384},
        {0x009E, tls::crypto::Aead::Aes128Gcm, tls::crypto::Hash::Sha256}, {0x009F, tls::crypto::Aead::Aes256Gcm, tls::crypto::Hash::Sha384},
        {0xC02B, tls::crypto::Aead::Aes128Gcm, tls::crypto::Hash::Sha256}, {0xC02C, tls::crypto::Aead::Aes256Gcm, tls::crypto::Hash::Sha384},
        {0xC02F, tls::crypto::Aead::Aes128Gcm, tls::crypto::Hash::Sha256}, {0xC030, tls::crypto::Aead::Aes256Gcm, tls::crypto::Hash::Sha384},
        {0xCCA8, tls::crypto::Aead::ChaCha20Poly1305, tls::crypto::Hash::Sha256}, {0xCCA9, tls::crypto::Aead::ChaCha20Poly1305, tls::crypto::Hash::Sha256},
        {0xCCAA, tls::crypto::Aead::ChaCha20Poly1305, tls::crypto::Hash::Sha256},
    };
    for (const Expect &e: supported) {
        const tls::CipherSuite *s = tls::findCipherSuite(0x0303, e.id);
        ASSERT_NE(s, nullptr) << std::hex << e.id;
        EXPECT_FALSE(s->tls13);
        EXPECT_EQ(s->aead, e.aead) << std::hex << e.id;
        EXPECT_EQ(s->hash, e.hash) << std::hex << e.id;
        EXPECT_EQ(tls::findCipherSuite(0x0304, e.id), nullptr) << "a TLS 1.2 suite is not valid under TLS 1.3";
        EXPECT_EQ(tls::findCipherSuite(0x0302, e.id), nullptr) << "TLS 1.1 and older are not supported";
    }
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0xC013), nullptr);   // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0x002F), nullptr);   // TLS_RSA_WITH_AES_128_CBC_SHA
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0xCCAB), nullptr);   // TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0xC0AC), nullptr);   // TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0x1301), nullptr);   // a TLS 1.3 suite under TLS 1.2
    EXPECT_EQ(tls::findCipherSuite(0x0303, 0x0000), nullptr);
}

TEST_F(TlsDecrypt, OpenSslTls12ConnectionsDecryptToTheKnownPlaintext) {
    const auto cases = loadCases("decrypt_tls12.json");
    ASSERT_EQ(cases.size(), 11u);   // every supported suite
    std::vector<uint16_t> seen;
    for (const Case &c: cases) {
        SCOPED_TRACE(c.name);
        seen.push_back(c.cipher);
        Prepared p(c);
        ASSERT_EQ(p.dec.availability(), DecryptStatus::Decrypted);
        for (Direction d: {Direction::ClientToServer, Direction::ServerToClient}) {
            const DirRun run = runDirection(p.dec, c, d);
            ASSERT_EQ(run.status.size(), 3u);   // Finished, application data, close_notify
            for (size_t i = 0; i < run.status.size(); ++i) EXPECT_EQ(run.status[i], DecryptStatus::Decrypted) << "record " << i;
            EXPECT_EQ(run.application, c.application[static_cast<size_t>(d)]);
            EXPECT_EQ(run.records[0].contentType, 22);          // the encrypted Finished: type 20, length 12, verify_data
            ASSERT_EQ(run.records[0].plaintext.size(), 16u);
            EXPECT_EQ(run.records[0].plaintext[0], 20);
            EXPECT_EQ(run.records[0].plaintext[3], 12);
            EXPECT_EQ(run.records[2].contentType, 21);          // alert: warning, close_notify
            EXPECT_EQ(hexOf(run.records[2].plaintext), "0100");
            for (size_t i = 0; i < run.records.size(); ++i) {
                EXPECT_EQ(run.records[i].sequence, i);          // sequence numbers start at 0 after the ChangeCipherSpec
                EXPECT_EQ(run.records[i].epoch, KeyEpoch::Application);
            }
            EXPECT_EQ(p.dec.sequence(d), 3u);
        }
    }
    std::sort(seen.begin(), seen.end());
    EXPECT_EQ(std::adjacent_find(seen.begin(), seen.end()), seen.end()) << "each suite once";
}

TEST_F(TlsDecrypt, Tls12WrongMasterSecretFailsEveryTag) {
    for (const Case &c: loadCases("decrypt_tls12.json")) {
        SCOPED_TRACE(c.name);
        std::string log = c.keylog;
        const size_t at = log.find("CLIENT_RANDOM ") + 14 + 64 + 1;   // first digit of the master secret
        log[at] = log[at] == '0' ? '1' : '0';
        Prepared p(c, log);
        for (Direction d: {Direction::ClientToServer, Direction::ServerToClient}) {
            const DirRun run = runDirection(p.dec, c, d);
            for (auto status: run.status) EXPECT_EQ(status, DecryptStatus::TagFailure);
            EXPECT_TRUE(run.application.empty());
        }
    }
}

TEST_F(TlsDecrypt, Tls12KeyBlockNeedsTheRightRandomsInTheRightOrder) {
    const Case c = loadCases("decrypt_tls12.json").front();
    Prepared ok(c);
    EXPECT_EQ(runDirection(ok.dec, c, Direction::ServerToClient).application, c.application[1]);
    tls::KeyStore store;
    store.parseText(c.keylog);
    tls::RecordDecryptor swapped(c.version, c.cipher, c.serverRandom, c.clientRandom, store.find(c.clientRandom));   // randoms exchanged
    for (auto status: runDirection(swapped, c, Direction::ServerToClient).status) EXPECT_EQ(status, DecryptStatus::TagFailure);
    tls::RecordDecryptor wrongServer(c.version, c.cipher, c.clientRandom, c.clientRandom, store.find(c.clientRandom));
    for (auto status: runDirection(wrongServer, c, Direction::ServerToClient).status) EXPECT_EQ(status, DecryptStatus::TagFailure);
}

TEST_F(TlsDecrypt, Tls12DirectionsUseTheirOwnKeys) {
    for (const char *file: {"decrypt_tls12.json"}) {
        for (const Case &c: loadCases(file)) {
            SCOPED_TRACE(c.name);
            Prepared p(c);
            const Rec &fromClient = c.records[0].front();
            auto r = p.dec.decrypt(Direction::ServerToClient, fromClient.type, fromClient.version, fromClient.fragment);   // client record, server keys
            EXPECT_EQ(r.status, DecryptStatus::TagFailure);
            EXPECT_TRUE(r.plaintext.empty());
        }
    }
}

TEST_F(TlsDecrypt, Tls12SequenceNumberIsPartOfTheAdditionalData) {
    for (const Case &c: loadCases("decrypt_tls12.json")) {
        SCOPED_TRACE(c.name);
        {   // the application data record is sequence number 1: opened as number 0 it fails (AAD for GCM, nonce and AAD for ChaCha)
            Prepared p(c);
            const Rec &data = c.records[0][1];
            EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, data.type, data.version, data.fragment).status, DecryptStatus::TagFailure);
            EXPECT_EQ(p.dec.sequence(Direction::ClientToServer), 1u);
            // the failed try used number 0, so the record now meets number 1, which is its own
            EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, data.type, data.version, data.fragment).status, DecryptStatus::Decrypted);
        }
        {   // setSequence puts a direction back on the right number
            Prepared p(c);
            p.dec.setSequence(Direction::ClientToServer, 1);
            const Rec &data = c.records[0][1];
            auto r = p.dec.decrypt(Direction::ClientToServer, data.type, data.version, data.fragment);
            EXPECT_EQ(r.status, DecryptStatus::Decrypted);
            EXPECT_EQ(r.contentType, 23);
        }
        {   // type and version are in the additional data too
            Prepared p(c);
            const Rec &fin = c.records[0][0];
            EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, 23, fin.version, fin.fragment).status, DecryptStatus::TagFailure);
            Prepared q(c);
            EXPECT_EQ(q.dec.decrypt(Direction::ClientToServer, fin.type, 0x0301, fin.fragment).status, DecryptStatus::TagFailure);
        }
    }
}

TEST_F(TlsDecrypt, Tls12NoKeyAndMalformed) {
    const Case c = loadCases("decrypt_tls12.json").front();
    const Rec &fin = c.records[0][0];
    {   // no entry
        tls::RecordDecryptor dec(c.version, c.cipher, c.clientRandom, c.serverRandom, nullptr);
        EXPECT_EQ(dec.availability(), DecryptStatus::NoKey);
        EXPECT_EQ(dec.decrypt(Direction::ClientToServer, fin.type, fin.version, fin.fragment).status, DecryptStatus::NoKey);
    }
    {   // only TLS 1.3 secrets
        tls::KeyStore store;
        store.parseText(logLine("CLIENT_TRAFFIC_SECRET_0", kClientAp) + logLine("SERVER_TRAFFIC_SECRET_0", kServerAp));
        tls::RecordDecryptor dec(c.version, c.cipher, c.clientRandom, c.serverRandom, store.find(randomA()));
        EXPECT_EQ(dec.availability(), DecryptStatus::NoKey);
        EXPECT_EQ(dec.decrypt(Direction::ServerToClient, fin.type, fin.version, fin.fragment).status, DecryptStatus::NoKey);
    }
    Prepared p(c);
    EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, fin.type, fin.version, {}).status, DecryptStatus::Malformed);
    EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, fin.type, fin.version, std::span<const uint8_t>(fin.fragment).first(15)).status, DecryptStatus::Malformed);
    EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, fin.type, fin.version, Bytes(16384 + 2048 + 1, 0)).status, DecryptStatus::Malformed);
    EXPECT_EQ(p.dec.sequence(Direction::ClientToServer), 0u);
    EXPECT_EQ(p.dec.decrypt(Direction::ClientToServer, fin.type, fin.version, fin.fragment).status, DecryptStatus::Decrypted);
}

TEST_F(TlsDecrypt, Tls12EveryDamagedOrCutRecordIsRejected) {
    for (const Case &c: loadCases("decrypt_tls12.json")) {
        SCOPED_TRACE(c.name);
        const Rec &fin = c.records[1][0];   // the server Finished (sequence 0, the first record of its direction)
        for (size_t i = 0; i < fin.fragment.size(); ++i) {
            Bytes bad = fin.fragment;
            bad[i] ^= 0x40;
            Prepared p(c);
            auto r = p.dec.decrypt(Direction::ServerToClient, fin.type, fin.version, bad);
            EXPECT_EQ(r.status, DecryptStatus::TagFailure) << i;
            EXPECT_TRUE(r.plaintext.empty());
        }
        for (size_t len = 0; len < fin.fragment.size(); ++len) {
            Prepared p(c);
            auto r = p.dec.decrypt(Direction::ServerToClient, fin.type, fin.version, std::span<const uint8_t>(fin.fragment).first(len));
            EXPECT_TRUE(r.status == DecryptStatus::Malformed || r.status == DecryptStatus::TagFailure) << len;
            EXPECT_TRUE(r.plaintext.empty());
        }
    }
}

TEST_F(TlsDecrypt, StaticRsaKeyLogLineDoesNotDisturbTheLookup) {
    // OpenSSL writes an "RSA <8 bytes> <pre-master>" line for static RSA key exchange next to CLIENT_RANDOM
    const auto cases = loadCases("decrypt_tls12.json");
    const auto rsa = std::find_if(cases.begin(), cases.end(), [](const Case &c) { return c.cipher == 0x009C; });
    ASSERT_NE(rsa, cases.end());
    ASSERT_NE(rsa->keylog.find("\nRSA "), std::string::npos);
    Prepared p(*rsa);
    EXPECT_EQ(runDirection(p.dec, *rsa, Direction::ServerToClient).application, rsa->application[1]);
}

TEST(TlsDecryptBackend, BuildsWithoutOpenSslReportItInsteadOfFailingSilently) {
    if (tls::crypto::available()) GTEST_SKIP() << "this build has OpenSSL; the stub is covered by IMSHARK_TLS_DECRYPT=OFF builds";
    Keys keys(rfc8448Log());
    tls::RecordDecryptor dec(0x0304, 0x1301, randomA(), randomB(), keys.entry());
    EXPECT_EQ(dec.availability(), DecryptStatus::NoBackend);
    auto r = open(dec, Direction::ClientToServer, kClientFinishedRecord);
    EXPECT_EQ(r.status, DecryptStatus::NoBackend);
    EXPECT_TRUE(r.plaintext.empty());
    tls::RecordDecryptor unsupported(0x0304, 0x1304, randomA(), randomB(), keys.entry());
    EXPECT_EQ(unsupported.availability(), DecryptStatus::UnsupportedSuite);   // still decided without the backend
}

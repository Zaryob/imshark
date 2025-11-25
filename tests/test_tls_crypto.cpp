// The libcrypto wrapper of the TLS decryptor (tls/crypto.h): HMAC, HKDF, the TLS 1.3 label functions, the TLS 1.2 PRF
// and AEAD open with tag verification.
//
// Oracles (nothing here is computed by the code under test):
//   - RFC 5869 appendix A test cases 1-3 (HKDF-SHA256); the OKM of case 2 and the PRKs were also recomputed with Python's hmac
//   - TLS 1.2 PRF: the widely used P_SHA256 / P_SHA384 vectors ("test label"); recomputed with the OpenSSL CLI:
//       openssl kdf -keylen 100 -kdfopt digest:SHA256 -kdfopt hexsecret:9bbe436ba940f017b17652849a71db35 \
//         -kdfopt hexseed:<hex("test label")>a0ba9f936cda311827a6f796ffd5198c -binary TLS1-PRF
//       openssl kdf -keylen 148 -kdfopt digest:SHA384 -kdfopt hexsecret:b80b733d6ceefcdc71566ea48e5567df \
//         -kdfopt hexseed:<hex("test label")>cd665cf6a8447dd6ff8b27555edb7465 -binary TLS1-PRF
//   - HKDF-Expand-Label / Derive-Secret: the TLS 1.3 key schedule of RFC 8448 section 3 (early secret ... application
//     traffic secrets, keys and IVs)
//   - AEAD: RFC 8439 section 2.8.2 (ChaCha20-Poly1305) and the AES-GCM test case 4 of the GCM specification (McGrew and
//     Viega) with the 256-bit key variant; ciphertext and tag recomputed with Node's crypto module
#include <gtest/gtest.h>

#include <string>

#include <tls/crypto.h>

#include "support.h"

namespace {
    using tls::crypto::Aead;
    using tls::crypto::AeadStatus;
    using tls::crypto::Bytes;
    using tls::crypto::Hash;

    Bytes bytesOf(const std::string &hexText) {
        Bytes out;
        for (char c: support::hex(hexText)) out.push_back(static_cast<uint8_t>(c));
        return out;
    }

    Bytes ascii(const std::string &s) { return Bytes(s.begin(), s.end()); }

    std::string hexOf(const Bytes &b) { return support::hexOf(std::string(b.begin(), b.end())); }

    std::string hexOf(const std::optional<Bytes> &b) { return b ? hexOf(*b) : "<nullopt>"; }

    class TlsCrypto : public ::testing::Test {
    protected:
        void SetUp() override {
            if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
        }
    };
}

TEST(TlsCryptoBackend, ReportsWhatTheBuildCanDo) {
    const std::string name = tls::crypto::backendName();
    if (tls::crypto::available()) {
        EXPECT_NE(name.find("OpenSSL 3"), std::string::npos) << name;
    } else {
        EXPECT_EQ(name, "TLS decryption is not available in this build");
        // the stub fails cleanly instead of returning data
        EXPECT_FALSE(tls::crypto::hmac(Hash::Sha256, {}, {}).has_value());
        Bytes out = {1, 2, 3};
        const Bytes key(16), nonce(12), data(32);
        EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes128Gcm, key, nonce, {}, data, out), AeadStatus::Unavailable);
        EXPECT_TRUE(out.empty());
    }
}

// ---- HKDF (RFC 5869 appendix A, SHA-256) ----------------------------------------------------------------------

TEST_F(TlsCrypto, HkdfRfc5869Case1) {
    const Bytes ikm = Bytes(22, 0x0b);
    const Bytes salt = bytesOf("000102030405060708090a0b0c");
    const Bytes info = bytesOf("f0f1f2f3f4f5f6f7f8f9");
    const auto prk = tls::crypto::hkdfExtract(Hash::Sha256, salt, ikm);
    EXPECT_EQ(hexOf(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    ASSERT_TRUE(prk.has_value());
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpand(Hash::Sha256, *prk, info, 42)),
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TEST_F(TlsCrypto, HkdfRfc5869Case2LongInputs) {
    Bytes ikm, salt, info;
    for (int i = 0x00; i <= 0x4f; ++i) ikm.push_back(static_cast<uint8_t>(i));
    for (int i = 0x60; i <= 0xaf; ++i) salt.push_back(static_cast<uint8_t>(i));
    for (int i = 0xb0; i <= 0xff; ++i) info.push_back(static_cast<uint8_t>(i));
    const auto prk = tls::crypto::hkdfExtract(Hash::Sha256, salt, ikm);
    EXPECT_EQ(hexOf(prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    ASSERT_TRUE(prk.has_value());
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpand(Hash::Sha256, *prk, info, 82)),
              "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
              "cc30c58179ec3e87c14c01d5c1f3434f1d87");
}

TEST_F(TlsCrypto, HkdfRfc5869Case3EmptySaltAndInfo) {
    const Bytes ikm = Bytes(22, 0x0b);
    const auto prk = tls::crypto::hkdfExtract(Hash::Sha256, {}, ikm);   // empty salt = HashLen zero bytes
    EXPECT_EQ(hexOf(prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    ASSERT_TRUE(prk.has_value());
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpand(Hash::Sha256, *prk, {}, 42)),
              "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

TEST_F(TlsCrypto, HkdfExpandLengthLimits) {
    const Bytes prk(32, 1);
    EXPECT_TRUE(tls::crypto::hkdfExpand(Hash::Sha256, prk, {}, 255 * 32).has_value());
    EXPECT_FALSE(tls::crypto::hkdfExpand(Hash::Sha256, prk, {}, 255 * 32 + 1).has_value());
    EXPECT_TRUE(tls::crypto::hkdfExpand(Hash::Sha384, Bytes(48, 1), {}, 255 * 48).has_value());
    EXPECT_FALSE(tls::crypto::hkdfExpand(Hash::Sha384, Bytes(48, 1), {}, 255 * 48 + 1).has_value());
    EXPECT_TRUE(tls::crypto::hkdfExpand(Hash::Sha256, prk, {}, 0)->empty());
}

TEST_F(TlsCrypto, HmacSha384OfTheRfc4231FirstCase) {
    // RFC 4231 test case 1: key 0x0b * 20, data "Hi There"
    EXPECT_EQ(hexOf(tls::crypto::hmac(Hash::Sha384, Bytes(20, 0x0b), ascii("Hi There"))),
              "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    EXPECT_EQ(hexOf(tls::crypto::hmac(Hash::Sha256, Bytes(20, 0x0b), ascii("Hi There"))),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

// ---- TLS 1.3 key schedule (RFC 8448 section 3, "Simple 1-RTT Handshake") --------------------------------------

TEST_F(TlsCrypto, Tls13KeyScheduleOfRfc8448) {
    const Bytes zeros(32, 0);
    const Bytes emptyHash = bytesOf("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");   // SHA-256 of ""
    const auto early = tls::crypto::hkdfExtract(Hash::Sha256, {}, zeros);
    EXPECT_EQ(hexOf(early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    ASSERT_TRUE(early.has_value());
    const auto derived = tls::crypto::deriveSecret(Hash::Sha256, *early, "derived", emptyHash);
    EXPECT_EQ(hexOf(derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    ASSERT_TRUE(derived.has_value());
    const Bytes ecdhe = bytesOf("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const auto handshake = tls::crypto::hkdfExtract(Hash::Sha256, *derived, ecdhe);
    EXPECT_EQ(hexOf(handshake), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    ASSERT_TRUE(handshake.has_value());

    const Bytes helloHash = bytesOf("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");   // ClientHello..ServerHello
    const auto clientHs = tls::crypto::deriveSecret(Hash::Sha256, *handshake, "c hs traffic", helloHash);
    const auto serverHs = tls::crypto::deriveSecret(Hash::Sha256, *handshake, "s hs traffic", helloHash);
    EXPECT_EQ(hexOf(clientHs), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
    EXPECT_EQ(hexOf(serverHs), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    ASSERT_TRUE(serverHs.has_value());
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, *serverHs, "key", {}, 16)), "3fce516009c21727d0f2e4e86ee403bc");
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, *serverHs, "iv", {}, 12)), "5d313eb2671276ee13000b30");

    const auto derived2 = tls::crypto::deriveSecret(Hash::Sha256, *handshake, "derived", emptyHash);
    ASSERT_TRUE(derived2.has_value());
    const auto master = tls::crypto::hkdfExtract(Hash::Sha256, *derived2, zeros);
    EXPECT_EQ(hexOf(master), "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    ASSERT_TRUE(master.has_value());
    const Bytes finishedHash = bytesOf("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");   // ClientHello..server Finished
    const auto clientAp = tls::crypto::deriveSecret(Hash::Sha256, *master, "c ap traffic", finishedHash);
    const auto serverAp = tls::crypto::deriveSecret(Hash::Sha256, *master, "s ap traffic", finishedHash);
    EXPECT_EQ(hexOf(clientAp), "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
    EXPECT_EQ(hexOf(serverAp), "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
    ASSERT_TRUE(serverAp.has_value());
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, *serverAp, "key", {}, 16)), "9f02283b6c9c07efc26bb9f2ac92e356");
    EXPECT_EQ(hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, *serverAp, "iv", {}, 12)), "cf782b88dd83549aadf1e984");
}

TEST_F(TlsCrypto, HkdfExpandLabelLimits) {
    const Bytes secret(32, 7);
    EXPECT_TRUE(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, std::string(249, 'x'), Bytes(255, 1), 32).has_value());
    EXPECT_FALSE(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, std::string(250, 'x'), {}, 32).has_value());
    EXPECT_FALSE(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, "key", Bytes(256, 1), 32).has_value());
    EXPECT_FALSE(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, "key", {}, 255 * 32 + 1).has_value());
    // the output length is part of the label info, so different lengths are not prefixes of each other
    EXPECT_NE(hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, "key", {}, 16)),
              hexOf(tls::crypto::hkdfExpandLabel(Hash::Sha256, secret, "key", {}, 32)).substr(0, 32));
}

// ---- TLS 1.2 PRF -----------------------------------------------------------------------------------------------

TEST_F(TlsCrypto, Tls12PrfSha256) {
    EXPECT_EQ(hexOf(tls::crypto::prf(Hash::Sha256, bytesOf("9bbe436ba940f017b17652849a71db35"), "test label",
                                    bytesOf("a0ba9f936cda311827a6f796ffd5198c"), 100)),
              "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
              "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");
}

TEST_F(TlsCrypto, Tls12PrfSha384) {
    EXPECT_EQ(hexOf(tls::crypto::prf(Hash::Sha384, bytesOf("b80b733d6ceefcdc71566ea48e5567df"), "test label",
                                    bytesOf("cd665cf6a8447dd6ff8b27555edb7465"), 148)),
              "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd"
              "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6"
              "91c8f3a26854308d5eaa3be85e0990703d73e56f");
}

TEST_F(TlsCrypto, Tls12PrfOutputIsAPrefixCodeAndBounded) {
    const Bytes secret = bytesOf("9bbe436ba940f017b17652849a71db35"), seed = bytesOf("a0ba9f936cda311827a6f796ffd5198c");
    const auto longer = tls::crypto::prf(Hash::Sha256, secret, "test label", seed, 100);
    const auto shorter = tls::crypto::prf(Hash::Sha256, secret, "test label", seed, 33);
    ASSERT_TRUE(longer && shorter);
    EXPECT_EQ(hexOf(shorter), hexOf(longer).substr(0, 66));
    EXPECT_TRUE(tls::crypto::prf(Hash::Sha256, secret, "x", seed, 0)->empty());
    EXPECT_FALSE(tls::crypto::prf(Hash::Sha256, secret, "x", seed, (1u << 20) + 1).has_value());
}

// ---- AEAD ------------------------------------------------------------------------------------------------------

namespace {
    struct AeadCase {
        Aead aead;
        std::string key, nonce, aad, plaintext, ciphertext, tag;
    };

    // RFC 8439 section 2.8.2: the plaintext is "Ladies and Gentlemen of the class of '99: If I could offer you only one tip ..."
    const std::string kSunscreen =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

    std::vector<AeadCase> aeadCases() {
        const std::string gcmPlain =
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        const std::string gcmAad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        return {
            {Aead::ChaCha20Poly1305, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "070000004041424344454647",
             "50515253c0c1c2c3c4c5c6c7", kSunscreen,
             "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3"
             "692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
             "1ae10b594f09e26a7e902ecbd0600691"},
            {Aead::Aes128Gcm, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", gcmAad, gcmPlain,
             "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
             "5bc94fbc3221a5db94fae95ae7121a47"},
            {Aead::Aes256Gcm, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", gcmAad, gcmPlain,
             "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
             "76fc6ece0f4e1768cddf8853bb2d551b"},
        };
    }

    Bytes joined(const std::string &ct, const std::string &tag) { return bytesOf(ct + tag); }
}

TEST_F(TlsCrypto, AeadOpensTheStandardVectors) {
    for (const auto &c: aeadCases()) {
        Bytes plain = {9};
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, bytesOf(c.key), bytesOf(c.nonce), bytesOf(c.aad), joined(c.ciphertext, c.tag), plain),
                  AeadStatus::Ok) << c.key;
        EXPECT_EQ(hexOf(plain), c.plaintext) << c.key;
    }
}

TEST_F(TlsCrypto, AeadTagFailureNeverReturnsPlaintext) {
    for (const auto &c: aeadCases()) {
        const Bytes key = bytesOf(c.key), nonce = bytesOf(c.nonce), aad = bytesOf(c.aad), good = joined(c.ciphertext, c.tag);
        Bytes plain;

        Bytes badTag = good;                                  // wrong tag
        badTag.back() ^= 1;
        plain = {1, 2, 3};
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, nonce, aad, badTag, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());

        Bytes badData = good;                                 // modified ciphertext
        badData[0] ^= 0x80;
        plain = {1, 2, 3};
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, nonce, aad, badData, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());

        Bytes badKey = key;                                   // wrong key
        badKey[3] ^= 1;
        plain = {1, 2, 3};
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, badKey, nonce, aad, good, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());

        Bytes badNonce = nonce;                               // wrong nonce
        badNonce[11] ^= 1;
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, badNonce, aad, good, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());

        Bytes badAad = aad;                                   // wrong additional data
        badAad[0] ^= 1;
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, nonce, badAad, good, plain), AeadStatus::TagFailure);
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, nonce, {}, good, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());

        Bytes shorter(good.begin(), good.end() - 1);          // truncated record (tag cut)
        EXPECT_EQ(tls::crypto::aeadOpen(c.aead, key, nonce, aad, shorter, plain), AeadStatus::TagFailure);
        EXPECT_TRUE(plain.empty());
    }
}

TEST_F(TlsCrypto, AeadRejectsBadSizes) {
    Bytes plain;
    const Bytes data(32, 0);
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes128Gcm, Bytes(15, 0), Bytes(12, 0), {}, data, plain), AeadStatus::BadInput);
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes128Gcm, Bytes(32, 0), Bytes(12, 0), {}, data, plain), AeadStatus::BadInput);
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes256Gcm, Bytes(16, 0), Bytes(12, 0), {}, data, plain), AeadStatus::BadInput);
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::ChaCha20Poly1305, Bytes(32, 0), Bytes(8, 0), {}, data, plain), AeadStatus::BadInput);
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes128Gcm, Bytes(16, 0), Bytes(12, 0), {}, Bytes(15, 0), plain), AeadStatus::BadInput);   // shorter than the tag
    EXPECT_TRUE(plain.empty());
}

TEST_F(TlsCrypto, AeadAcceptsEmptyPlaintext) {
    // 16 bytes of tag over nothing: authenticate-only message (AES-128-GCM, zero key and nonce: GCM spec test case 1)
    Bytes plain = {1};
    EXPECT_EQ(tls::crypto::aeadOpen(Aead::Aes128Gcm, Bytes(16, 0), Bytes(12, 0), {}, bytesOf("58e2fccefa7e3061367f1d57a4e7455a"), plain),
              AeadStatus::Ok);
    EXPECT_TRUE(plain.empty());
}

#include "tls/crypto.h"

#include <algorithm>

#ifdef IMSHARK_HAVE_TLS_DECRYPT
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#endif

namespace tls::crypto {
#ifdef IMSHARK_HAVE_TLS_DECRYPT
    namespace {
        constexpr size_t kMaxPrfLength = 1u << 20;

        const EVP_MD *digest(Hash h) { return h == Hash::Sha256 ? EVP_sha256() : EVP_sha384(); }

        const EVP_CIPHER *cipherOf(Aead a) {
            switch (a) {
                case Aead::Aes128Gcm: return EVP_aes_128_gcm();
                case Aead::Aes256Gcm: return EVP_aes_256_gcm();
                case Aead::ChaCha20Poly1305: return EVP_chacha20_poly1305();
            }
            return nullptr;
        }

        // HMAC over the concatenation of up to three pieces (the callers of HKDF / PRF build such inputs)
        std::optional<Bytes> hmac3(Hash hash, ByteView key, ByteView a, ByteView b = {}, ByteView c = {}) {
            Bytes data;
            data.reserve(a.size() + b.size() + c.size());
            data.insert(data.end(), a.begin(), a.end());
            data.insert(data.end(), b.begin(), b.end());
            data.insert(data.end(), c.begin(), c.end());
            return hmac(hash, key, data);
        }
    } // namespace

    bool available() { return true; }
    const char *backendName() { return OpenSSL_version(OPENSSL_VERSION); }

    std::optional<Bytes> hmac(Hash hash, ByteView key, ByteView data) {
        static const uint8_t kEmpty = 0;   // HMAC() wants non-null pointers even for empty input
        Bytes out(EVP_MAX_MD_SIZE);
        unsigned int len = 0;
        if (key.size() > static_cast<size_t>(INT32_MAX)) return std::nullopt;
        if (!HMAC(digest(hash), key.empty() ? &kEmpty : key.data(), static_cast<int>(key.size()),
                  data.empty() ? &kEmpty : data.data(), data.size(), out.data(), &len)
            || len != hashLength(hash))
            return std::nullopt;
        out.resize(len);
        return out;
    }

    std::optional<Bytes> hkdfExtract(Hash hash, ByteView salt, ByteView ikm) {
        const Bytes zeros(hashLength(hash), 0);
        return hmac(hash, salt.empty() ? ByteView(zeros) : salt, ikm);
    }

    std::optional<Bytes> hkdfExpand(Hash hash, ByteView prk, ByteView info, size_t length) {
        const size_t hl = hashLength(hash);
        if (length > 255 * hl) return std::nullopt;
        Bytes okm, t;
        okm.reserve(length + hl);
        for (uint8_t counter = 1; okm.size() < length; ++counter) {
            const uint8_t ctr[1] = {counter};
            auto next = hmac3(hash, prk, t, info, ctr);
            if (!next) return std::nullopt;
            t = std::move(*next);
            okm.insert(okm.end(), t.begin(), t.end());
        }
        okm.resize(length);
        return okm;
    }

    std::optional<Bytes> hkdfExpandLabel(Hash hash, ByteView secret, std::string_view label, ByteView context, size_t length) {
        static constexpr std::string_view kPrefix = "tls13 ";
        if (label.size() > 255 - kPrefix.size() || context.size() > 255 || length > 0xFFFF) return std::nullopt;
        // struct { uint16 length; opaque label<7..255> = "tls13 " + Label; opaque context<0..255>; } HkdfLabel
        Bytes info;
        info.reserve(4 + kPrefix.size() + label.size() + context.size());
        info.push_back(static_cast<uint8_t>(length >> 8));
        info.push_back(static_cast<uint8_t>(length));
        info.push_back(static_cast<uint8_t>(kPrefix.size() + label.size()));
        info.insert(info.end(), kPrefix.begin(), kPrefix.end());
        info.insert(info.end(), label.begin(), label.end());
        info.push_back(static_cast<uint8_t>(context.size()));
        info.insert(info.end(), context.begin(), context.end());
        return hkdfExpand(hash, secret, info, length);
    }

    std::optional<Bytes> deriveSecret(Hash hash, ByteView secret, std::string_view label, ByteView transcriptHash) {
        return hkdfExpandLabel(hash, secret, label, transcriptHash, hashLength(hash));
    }

    std::optional<Bytes> prf(Hash hash, ByteView secret, std::string_view label, ByteView seed, size_t length) {
        if (length > kMaxPrfLength) return std::nullopt;
        Bytes labelSeed(label.begin(), label.end());
        labelSeed.insert(labelSeed.end(), seed.begin(), seed.end());
        Bytes out;
        out.reserve(length + hashLength(hash));
        Bytes a = labelSeed;                                   // A(0)
        while (out.size() < length) {
            auto next = hmac(hash, secret, a);                 // A(i) = HMAC(secret, A(i-1))
            if (!next) return std::nullopt;
            a = std::move(*next);
            auto block = hmac3(hash, secret, a, labelSeed);    // HMAC(secret, A(i) + label + seed)
            if (!block) return std::nullopt;
            out.insert(out.end(), block->begin(), block->end());
        }
        out.resize(length);
        return out;
    }

    AeadStatus aeadOpen(Aead aead, ByteView key, ByteView nonce, ByteView aad, ByteView ciphertextAndTag, Bytes &plaintext) {
        plaintext.clear();
        const EVP_CIPHER *cipher = cipherOf(aead);
        if (!cipher || key.size() != aeadKeyLength(aead) || nonce.size() != kAeadNonceLength
            || ciphertextAndTag.size() < kAeadTagLength || ciphertextAndTag.size() > static_cast<size_t>(INT32_MAX) / 2
            || aad.size() > static_cast<size_t>(INT32_MAX))
            return AeadStatus::BadInput;

        const size_t ctLen = ciphertextAndTag.size() - kAeadTagLength;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return AeadStatus::BadInput;
        Bytes out(ctLen + EVP_MAX_BLOCK_LENGTH);
        AeadStatus status = AeadStatus::TagFailure;
        int n = 0;
        bool ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1
                  && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1
                  && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
        if (ok && !aad.empty()) ok = EVP_DecryptUpdate(ctx, nullptr, &n, aad.data(), static_cast<int>(aad.size())) == 1;
        int produced = 0;
        if (ok && ctLen > 0) {
            ok = EVP_DecryptUpdate(ctx, out.data(), &n, ciphertextAndTag.data(), static_cast<int>(ctLen)) == 1;
            produced = n;
        }
        uint8_t tag[kAeadTagLength];
        std::copy_n(ciphertextAndTag.data() + ctLen, kAeadTagLength, tag);
        if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagLength), tag) == 1;
        if (ok) {
            // EVP_DecryptFinal_ex compares the tag; nothing is released unless it matches
            ok = EVP_DecryptFinal_ex(ctx, out.data() + produced, &n) == 1 && produced + n == static_cast<int>(ctLen);
        }
        EVP_CIPHER_CTX_free(ctx);
        if (ok) {
            out.resize(ctLen);
            plaintext = std::move(out);
            status = AeadStatus::Ok;
        } else {
            OPENSSL_cleanse(out.data(), out.size());   // unauthenticated plaintext
        }
        return status;
    }
#else
    bool available() { return false; }
    const char *backendName() { return "TLS decryption is not available in this build"; }
    std::optional<Bytes> hmac(Hash, ByteView, ByteView) { return std::nullopt; }
    std::optional<Bytes> hkdfExtract(Hash, ByteView, ByteView) { return std::nullopt; }
    std::optional<Bytes> hkdfExpand(Hash, ByteView, ByteView, size_t) { return std::nullopt; }
    std::optional<Bytes> hkdfExpandLabel(Hash, ByteView, std::string_view, ByteView, size_t) { return std::nullopt; }
    std::optional<Bytes> deriveSecret(Hash, ByteView, std::string_view, ByteView) { return std::nullopt; }
    std::optional<Bytes> prf(Hash, ByteView, std::string_view, ByteView, size_t) { return std::nullopt; }
    AeadStatus aeadOpen(Aead, ByteView, ByteView, ByteView, ByteView, Bytes &plaintext) {
        plaintext.clear();
        return AeadStatus::Unavailable;
    }
#endif
} // namespace tls::crypto

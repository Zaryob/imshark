#pragma once

// The cryptography TLS decryption needs, as a thin wrapper around OpenSSL 3 libcrypto: HMAC, HKDF (RFC 5869) with the
// TLS 1.3 labels (RFC 8446 section 7.1), the TLS 1.2 PRF (RFC 5246 section 5) and AEAD *open* (decrypt + tag check) for
// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. Nothing here knows about records or cipher suite numbers; that is
// tls/record_decryptor.h.
//
// Build: the OpenSSL implementation is compiled when CMake found OpenSSL 3 and IMSHARK_TLS_DECRYPT is ON (the
// compile definition IMSHARK_HAVE_TLS_DECRYPT). Otherwise the same functions exist as a stub: available() is false,
// backendName() says "TLS decryption is not available in this build" and every operation fails (std::nullopt /
// AeadStatus::Unavailable). Callers can therefore link and call unconditionally.
//
// Everything is pure and thread safe (no shared state). Inputs are byte spans, outputs fresh vectors; a failed call
// never returns partial output.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace tls::crypto {
    using Bytes = std::vector<uint8_t>;
    using ByteView = std::span<const uint8_t>;

    /// True when this build can do cryptography (OpenSSL 3 linked in).
    bool available();
    /// "OpenSSL 3.x.y ..." or "TLS decryption is not available in this build".
    const char *backendName();

    /// The hash of a cipher suite: SHA-256 (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 and their TLS 1.2
    /// namesakes) or SHA-384 (the AES-256-GCM suites).
    enum class Hash : uint8_t { Sha256, Sha384 };
    constexpr size_t hashLength(Hash h) { return h == Hash::Sha256 ? 32 : 48; }

    /// HMAC(key, data). std::nullopt only if the backend is unavailable.
    std::optional<Bytes> hmac(Hash hash, ByteView key, ByteView data);

    /// HKDF-Extract(salt, ikm) = HMAC(salt, ikm); an empty salt means HashLen zero bytes (RFC 5869 section 2.2).
    std::optional<Bytes> hkdfExtract(Hash hash, ByteView salt, ByteView ikm);

    /// HKDF-Expand(prk, info, length). Fails when length > 255 * HashLen.
    std::optional<Bytes> hkdfExpand(Hash hash, ByteView prk, ByteView info, size_t length);

    /// TLS 1.3 HKDF-Expand-Label(secret, label, context, length): `label` is given WITHOUT the "tls13 " prefix ("key",
    /// "iv", "traffic upd", "c hs traffic", ...). Fails when the label is longer than 249 bytes, the context longer than
    /// 255 or the length does not fit HKDF-Expand / 16 bits.
    std::optional<Bytes> hkdfExpandLabel(Hash hash, ByteView secret, std::string_view label, ByteView context, size_t length);

    /// TLS 1.3 Derive-Secret(secret, label, transcriptHash) = HKDF-Expand-Label(secret, label, transcriptHash, HashLen);
    /// the caller passes the already computed Transcript-Hash.
    std::optional<Bytes> deriveSecret(Hash hash, ByteView secret, std::string_view label, ByteView transcriptHash);

    /// TLS 1.2 PRF(secret, label, seed) = P_hash(secret, label + seed), `length` bytes of output (RFC 5246 section 5; the
    /// hash is SHA-256 for most suites and SHA-384 for the *_SHA384 suites, RFC 5288). Fails when length > 1 MiB.
    std::optional<Bytes> prf(Hash hash, ByteView secret, std::string_view label, ByteView seed, size_t length);

    enum class Aead : uint8_t { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305 };
    constexpr size_t aeadKeyLength(Aead a) { return a == Aead::Aes128Gcm ? 16 : 32; }
    constexpr size_t kAeadNonceLength = 12;   // all three use a 96-bit nonce
    constexpr size_t kAeadTagLength = 16;     // and a 128-bit tag

    enum class AeadStatus : uint8_t {
        Ok,            // plaintext was produced and the tag verified
        TagFailure,    // the tag does not match: wrong key, nonce, AAD or modified data. No plaintext is returned.
        BadInput,      // key / nonce length wrong or the input is shorter than the tag
        Unavailable,   // built without OpenSSL
    };

    /// Decrypts `ciphertextAndTag` (ciphertext followed by the 16 byte tag) and verifies the tag over `aad`. `plaintext`
    /// is filled only when the result is Ok (it is cleared otherwise, so unauthenticated data never leaks out).
    AeadStatus aeadOpen(Aead aead, ByteView key, ByteView nonce, ByteView aad, ByteView ciphertextAndTag, Bytes &plaintext);
} // namespace tls::crypto

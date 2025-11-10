#pragma once

// TLS key material: the NSS key log format (the file SSLKEYLOGFILE points to) and the store the decryptor looks secrets
// up in. No cryptography happens here; this only parses, validates and indexes the secrets.
//
// Where the secrets come from:
//   - a key log file or text given by the user: KeyStore::loadFile() / parseText()
//   - the Decryption Secrets Blocks of a pcapng file (secrets type 0x544c534b = TLS key log, same text format); the
//     capture reader feeds them into the same parser
//
// Lookup: a TLS connection is identified by the 32 byte random of its ClientHello, which is the first field of every
// key log line (the tls session table of dissect::SessionTables records it for each connection while the capture is
// loaded). KeyStore::find(clientRandom) returns every secret known for that connection:
//   CLIENT_RANDOM                      TLS <= 1.2 master secret (48 bytes)
//   CLIENT_EARLY_TRAFFIC_SECRET        TLS 1.3 0-RTT client secret (32 or 48 bytes, depends on the cipher suite hash)
//   CLIENT_HANDSHAKE_TRAFFIC_SECRET    TLS 1.3 client handshake secret
//   SERVER_HANDSHAKE_TRAFFIC_SECRET    TLS 1.3 server handshake secret
//   CLIENT_TRAFFIC_SECRET_0            TLS 1.3 first client application secret
//   SERVER_TRAFFIC_SECRET_0            TLS 1.3 first server application secret
//   EXPORTER_SECRET                    TLS 1.3 exporter master secret
//
// Parsing is tolerant: comments (#) and blank lines are skipped, a malformed line (wrong field count, bad hex, wrong
// length) is counted and described in KeyLogStats but never stops the parse. Lines with other labels (for example the
// key update secrets SERVER_TRAFFIC_SECRET_1..N or "RSA ..." lines) are counted as `unknown` and ignored.
//
// Thread safety: none. Add keys while no detail building runs.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace tls {
    using ClientRandom = std::array<uint8_t, 32>;

    enum class SecretKind : uint8_t {
        MasterSecret = 0,            // CLIENT_RANDOM (TLS 1.2 and older)
        ClientEarlyTraffic,          // CLIENT_EARLY_TRAFFIC_SECRET
        ClientHandshakeTraffic,      // CLIENT_HANDSHAKE_TRAFFIC_SECRET
        ServerHandshakeTraffic,      // SERVER_HANDSHAKE_TRAFFIC_SECRET
        ClientTraffic0,              // CLIENT_TRAFFIC_SECRET_0
        ServerTraffic0,              // SERVER_TRAFFIC_SECRET_0
        Exporter,                    // EXPORTER_SECRET
    };
    constexpr size_t kSecretKinds = 7;

    /// The label a secret has in the key log file ("CLIENT_RANDOM", ...).
    const char *secretLabel(SecretKind kind);

    /// One secret: 48 bytes at most (the master secret, or a traffic secret of a SHA-256 / SHA-384 cipher suite).
    struct Secret {
        uint8_t length = 0;                    // 0 = not known
        std::array<uint8_t, 48> bytes{};
        bool present() const { return length != 0; }
        std::string hex() const;               // lower case hex of the secret
    };

    /// Everything known about one TLS connection (all secrets that carried its client random).
    struct KeyEntry {
        std::array<Secret, kSecretKinds> secrets;
        const Secret &get(SecretKind kind) const { return secrets[static_cast<size_t>(kind)]; }
        bool has(SecretKind kind) const { return get(kind).present(); }
        /// Any of the TLS 1.3 handshake / application traffic secrets (the ones that decrypt records).
        bool hasTls13TrafficSecret() const;
        size_t secretCount() const;
    };

    /// What parsing one piece of key log text found.
    struct KeyLogStats {
        size_t lines = 0;        // lines that are neither blank nor comments
        size_t accepted = 0;     // secrets stored (a repeated identical line counts too)
        size_t malformed = 0;    // known label but wrong field count / hex / length, or a line that is too long
        size_t unknown = 0;      // a label this reader does not use
        size_t dropped = 0;      // valid but not stored because the store is full
        std::vector<std::string> errors;   // "line N: reason" for the first malformed lines (capped)

        static constexpr size_t kMaxErrors = 20;
        void add(const KeyLogStats &other);
    };

    /// How a connection's key material looks for the "Key material:" line of the detail tree.
    enum class KeyAvailability { NotFound, Tls12MasterSecret, Tls13TrafficSecrets };
    /// "not found" / "available (TLS 1.2 master secret)" / "available (TLS 1.3 traffic secrets)"
    const char *availabilityText(KeyAvailability a);

    /// Decides what `entry` offers for a connection that negotiated `version` (0x0303 = TLS 1.2, 0x0304 = TLS 1.3; 0 =
    /// not known). A TLS 1.3 connection needs a traffic secret, an older one the master secret; when the version is
    /// unknown whatever is present counts. An entry with only an exporter or early secret is NotFound.
    KeyAvailability classify(const KeyEntry *entry, uint16_t version);

    class KeyStore {
    public:
        static constexpr size_t kMaxEntries = 200000;        // distinct client randoms (about 400 bytes each)
        static constexpr size_t kMaxLineLength = 4096;       // longer lines are malformed
        static constexpr uint64_t kMaxFileSize = 256ull << 20;

        /// Adds the secrets found in key log `text` (any mix of \n and \r\n line ends). Later lines replace earlier
        /// secrets of the same label and client random.
        KeyLogStats parseText(std::string_view text);

        /// Reads a key log file (`path` is UTF-8). Returns false and sets `error` if it cannot be read; `stats` is
        /// filled in either way (empty on failure).
        bool loadFile(const std::string &path, KeyLogStats &stats, std::string &error);

        /// The secrets of the connection whose ClientHello random is `clientRandom`; nullptr if there are none.
        const KeyEntry *find(const ClientRandom &clientRandom) const;
        const KeyEntry *find(const uint8_t *random32) const;

        /// Copies every entry of `other` into this store (an entry of `other` wins per secret).
        void merge(const KeyStore &other);
        void clear() { entries_.clear(); }

        size_t entryCount() const { return entries_.size(); }
        bool empty() const { return entries_.empty(); }
        size_t secretCount() const;

    private:
        struct Hash {
            size_t operator()(const ClientRandom &r) const {
                size_t h = 1469598103934665603ull;   // FNV-1a over all bytes: a capture file is not trusted to hold random data
                for (uint8_t b: r) h = (h ^ b) * 1099511628211ull;
                return h;
            }
        };
        std::unordered_map<ClientRandom, KeyEntry, Hash> entries_;
    };
} // namespace tls

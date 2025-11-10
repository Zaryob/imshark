#include "keylog.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace tls {
    namespace {
        struct LabelInfo {
            const char *label;
            SecretKind kind;
            bool master;        // exactly 48 bytes; the traffic secrets are 32 or 48 (SHA-256 / SHA-384)
        };
        constexpr LabelInfo kLabels[] = {
            {"CLIENT_RANDOM", SecretKind::MasterSecret, true},
            {"CLIENT_EARLY_TRAFFIC_SECRET", SecretKind::ClientEarlyTraffic, false},
            {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", SecretKind::ClientHandshakeTraffic, false},
            {"SERVER_HANDSHAKE_TRAFFIC_SECRET", SecretKind::ServerHandshakeTraffic, false},
            {"CLIENT_TRAFFIC_SECRET_0", SecretKind::ClientTraffic0, false},
            {"SERVER_TRAFFIC_SECRET_0", SecretKind::ServerTraffic0, false},
            {"EXPORTER_SECRET", SecretKind::Exporter, false},
        };

        int hexValue(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        // Decodes `text` into exactly `bytes` bytes; false if the length or a digit is wrong.
        bool decodeHex(std::string_view text, uint8_t *out, size_t bytes) {
            if (text.size() != bytes * 2) return false;
            for (size_t i = 0; i < bytes; ++i) {
                const int hi = hexValue(text[2 * i]), lo = hexValue(text[2 * i + 1]);
                if (hi < 0 || lo < 0) return false;
                out[i] = static_cast<uint8_t>(hi * 16 + lo);
            }
            return true;
        }

        bool isBlank(char c) { return c == ' ' || c == '\t'; }

        // Splits a line into at most `max` blank separated tokens; returns the number found (max + 1 = too many).
        size_t tokenize(std::string_view line, std::string_view *tokens, size_t max) {
            size_t count = 0, i = 0;
            while (i < line.size()) {
                while (i < line.size() && isBlank(line[i])) ++i;
                if (i >= line.size()) break;
                const size_t start = i;
                while (i < line.size() && !isBlank(line[i])) ++i;
                if (count == max) return max + 1;
                tokens[count++] = line.substr(start, i - start);
            }
            return count;
        }
    } // namespace

    const char *secretLabel(SecretKind kind) {
        for (const auto &l: kLabels) if (l.kind == kind) return l.label;
        return "";
    }

    std::string Secret::hex() const {
        static const char *digits = "0123456789abcdef";
        std::string out;
        for (size_t i = 0; i < length; ++i) {
            out += digits[bytes[i] >> 4];
            out += digits[bytes[i] & 15];
        }
        return out;
    }

    bool KeyEntry::hasTls13TrafficSecret() const {
        return has(SecretKind::ClientHandshakeTraffic) || has(SecretKind::ServerHandshakeTraffic) ||
               has(SecretKind::ClientTraffic0) || has(SecretKind::ServerTraffic0);
    }

    size_t KeyEntry::secretCount() const {
        return static_cast<size_t>(std::count_if(secrets.begin(), secrets.end(), [](const Secret &s) { return s.present(); }));
    }

    void KeyLogStats::add(const KeyLogStats &o) {
        lines += o.lines;
        accepted += o.accepted;
        malformed += o.malformed;
        unknown += o.unknown;
        dropped += o.dropped;
        for (const auto &e: o.errors) {
            if (errors.size() >= kMaxErrors) break;
            errors.push_back(e);
        }
    }

    const char *availabilityText(KeyAvailability a) {
        switch (a) {
            case KeyAvailability::Tls12MasterSecret: return "available (TLS 1.2 master secret)";
            case KeyAvailability::Tls13TrafficSecrets: return "available (TLS 1.3 traffic secrets)";
            default: return "not found";
        }
    }

    KeyAvailability classify(const KeyEntry *entry, uint16_t version) {
        if (!entry) return KeyAvailability::NotFound;
        const bool master = entry->has(SecretKind::MasterSecret), traffic = entry->hasTls13TrafficSecret();
        if (version >= 0x0304) {
            if (traffic) return KeyAvailability::Tls13TrafficSecrets;
            return master ? KeyAvailability::Tls12MasterSecret : KeyAvailability::NotFound;
        }
        if (master) return KeyAvailability::Tls12MasterSecret;
        return traffic ? KeyAvailability::Tls13TrafficSecrets : KeyAvailability::NotFound;
    }

    KeyLogStats KeyStore::parseText(std::string_view text) {
        KeyLogStats stats;
        size_t lineNo = 0, pos = 0;
        auto malformed = [&](const std::string &why) {
            ++stats.malformed;
            if (stats.errors.size() < KeyLogStats::kMaxErrors) stats.errors.push_back("line " + std::to_string(lineNo) + ": " + why);
        };
        while (pos < text.size()) {
            size_t end = text.find('\n', pos);
            if (end == std::string_view::npos) end = text.size();
            std::string_view line = text.substr(pos, end - pos);
            pos = end + 1;
            ++lineNo;
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

            size_t first = 0;
            while (first < line.size() && isBlank(line[first])) ++first;
            if (first == line.size() || line[first] == '#') continue;           // blank or comment
            ++stats.lines;
            if (line.size() > kMaxLineLength) { malformed("line is too long"); continue; }

            std::string_view tokens[4];
            const size_t count = tokenize(line, tokens, 3);
            const LabelInfo *info = nullptr;
            for (const auto &l: kLabels) if (tokens[0] == l.label) info = &l;
            if (!info) { ++stats.unknown; continue; }
            if (count != 3) { malformed(std::string(info->label) + " needs a client random and a secret"); continue; }

            ClientRandom random;
            if (!decodeHex(tokens[1], random.data(), random.size())) { malformed("client random is not 64 hex digits"); continue; }

            Secret secret;
            const size_t bytes = tokens[2].size() / 2;
            const bool lengthOk = info->master ? bytes == 48 : (bytes == 32 || bytes == 48);
            if (tokens[2].size() % 2 != 0 || !lengthOk) {
                malformed(std::string(info->label) + (info->master ? " secret must be 48 bytes (96 hex digits)" : " secret must be 32 or 48 bytes (64 or 96 hex digits)"));
                continue;
            }
            if (!decodeHex(tokens[2], secret.bytes.data(), bytes)) { malformed("secret is not hex"); continue; }
            secret.length = static_cast<uint8_t>(bytes);

            auto it = entries_.find(random);
            if (it == entries_.end()) {
                if (entries_.size() >= kMaxEntries) { ++stats.dropped; continue; }
                it = entries_.emplace(random, KeyEntry{}).first;
            }
            it->second.secrets[static_cast<size_t>(info->kind)] = secret;
            ++stats.accepted;
        }
        return stats;
    }

    bool KeyStore::loadFile(const std::string &path, KeyLogStats &stats, std::string &error) {
        stats = KeyLogStats();
        error.clear();
        std::error_code ec;
        const std::filesystem::path p(std::u8string(reinterpret_cast<const char8_t *>(path.data()), path.size()));
        const auto size = std::filesystem::file_size(p, ec);
        if (ec) { error = "Cannot read key log file " + path; return false; }
        if (size > kMaxFileSize) { error = "Key log file " + path + " is too large"; return false; }
        std::ifstream file(p, std::ios::binary);
        if (!file) { error = "Cannot read key log file " + path; return false; }
        std::string text(static_cast<size_t>(size), '\0');
        if (size > 0 && !file.read(text.data(), static_cast<std::streamsize>(size))) { error = "Cannot read key log file " + path; return false; }
        stats = parseText(text);
        return true;
    }

    const KeyEntry *KeyStore::find(const ClientRandom &clientRandom) const {
        const auto it = entries_.find(clientRandom);
        return it == entries_.end() ? nullptr : &it->second;
    }

    const KeyEntry *KeyStore::find(const uint8_t *random32) const {
        ClientRandom r;
        std::memcpy(r.data(), random32, r.size());
        return find(r);
    }

    void KeyStore::merge(const KeyStore &other) {
        for (const auto &[random, entry]: other.entries_) {
            auto it = entries_.find(random);
            if (it == entries_.end()) {
                if (entries_.size() >= kMaxEntries) continue;
                it = entries_.emplace(random, KeyEntry{}).first;
            }
            for (size_t i = 0; i < kSecretKinds; ++i) {
                if (entry.secrets[i].present()) it->second.secrets[i] = entry.secrets[i];
            }
        }
    }

    size_t KeyStore::secretCount() const {
        size_t n = 0;
        for (const auto &kv: entries_) n += kv.second.secretCount();
        return n;
    }
} // namespace tls

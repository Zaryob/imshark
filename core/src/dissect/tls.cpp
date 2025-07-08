// TLS / SSL records, recognised by the record header (any port). Handshake messages are decoded far enough
// to show the message type, the client's server name (SNI), versions and the chosen cipher suite; encrypted
// content is only counted.
#include "protocols.h"

#include "util.h"

#include <algorithm>

using packet::Field;

namespace {
    using namespace dissect;

    const char *contentTypeName(uint8_t t) {
        switch (t) {
            case 20: return "Change Cipher Spec";
            case 21: return "Alert";
            case 22: return "Handshake";
            case 23: return "Application Data";
            case 24: return "Heartbeat";
            default: return "Unknown";
        }
    }

    const char *handshakeName(uint8_t t) {
        switch (t) {
            case 0: return "Hello Request";
            case 1: return "Client Hello";
            case 2: return "Server Hello";
            case 4: return "New Session Ticket";
            case 5: return "End of Early Data";
            case 8: return "Encrypted Extensions";
            case 11: return "Certificate";
            case 12: return "Server Key Exchange";
            case 13: return "Certificate Request";
            case 14: return "Server Hello Done";
            case 15: return "Certificate Verify";
            case 16: return "Client Key Exchange";
            case 20: return "Finished";
            case 24: return "Key Update";
            default: return "Handshake message";
        }
    }

    std::string versionName(uint16_t v) {
        switch (v) {
            case 0x0300: return "SSL 3.0";
            case 0x0301: return "TLS 1.0";
            case 0x0302: return "TLS 1.1";
            case 0x0303: return "TLS 1.2";
            case 0x0304: return "TLS 1.3";
            default: return hexString(v, 4);
        }
    }

    std::string cipherName(uint16_t c) {
        switch (c) {
            case 0x1301: return "TLS_AES_128_GCM_SHA256";
            case 0x1302: return "TLS_AES_256_GCM_SHA384";
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
            case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
            case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
            case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
            case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
            case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
            case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
            case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
            case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
            case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
            default: return hexString(c, 4);
        }
    }

    // A record header looks plausible: content type 20..24, version 3.0 - 3.4, sane length
    bool plausibleRecord(const char *d, size_t n) {
        if (n < 5) return false;
        const uint8_t type = static_cast<uint8_t>(d[0]);
        const uint8_t major = static_cast<uint8_t>(d[1]), minor = static_cast<uint8_t>(d[2]);
        const size_t len = be16(d + 3);
        return type >= 20 && type <= 24 && major == 3 && minor <= 4 && len > 0 && len <= 16384 + 2048;
    }

    struct Hello {
        std::string serverName;
        std::string alpn;
        uint16_t supportedVersion = 0;   // highest from the supported_versions extension
        uint16_t cipher = 0;             // ServerHello's chosen suite
        uint16_t version = 0;            // legacy version field
    };

    // Walks the extensions block [p, p+n); fills `h` and (when `tree`) adds nodes
    void parseExtensions(Context &ctx, const char *base, const char *p, size_t n, bool client, Hello &h, Field *tree) {
        const size_t o = ctx.offsetOf(base);
        size_t i = 0;
        while (n - i >= 4) {
            const uint16_t type = be16(p + i), len = be16(p + i + 2);
            const size_t body = i + 4;
            if (n - body < len) break;
            const char *d = p + body;
            std::string note;
            if (type == 0 && client && len >= 5) { // server_name: list length(2), name type(1), name length(2), name
                const size_t nameLen = be16(d + 3);
                if (5 + nameLen <= len && d[2] == 0) {
                    h.serverName.assign(d + 5, nameLen);
                    note = "server_name: " + h.serverName;
                }
            } else if (type == 43) { // supported_versions
                if (client && len >= 3) {
                    for (size_t k = 1; k + 1 < len; k += 2) h.supportedVersion = std::max<uint16_t>(h.supportedVersion, be16(d + k));
                } else if (!client && len == 2) {
                    h.supportedVersion = be16(d);
                }
                note = "supported_versions";
            } else if (type == 16 && len >= 4) { // ALPN: list length(2), then length-prefixed protocols
                std::string all;
                for (size_t k = 2; k < len;) {
                    const size_t pl = static_cast<uint8_t>(d[k]);
                    if (k + 1 + pl > len) break;
                    if (!all.empty()) all += ", ";
                    all.append(d + k + 1, pl);
                    k += 1 + pl;
                }
                if (h.alpn.empty()) h.alpn = all;
                note = "application_layer_protocol_negotiation: " + all;
            } else {
                static const struct { uint16_t t; const char *n; } names[] = {{10, "supported_groups"}, {11, "ec_point_formats"}, {13, "signature_algorithms"},
                                                                          {23, "extended_master_secret"}, {35, "session_ticket"}, {51, "key_share"},
                                                                          {45, "psk_key_exchange_modes"}, {65281, "renegotiation_info"}, {5, "status_request"}};
                for (const auto &e: names) if (e.t == type) note = e.n;
                if (note.empty()) note = "extension " + std::to_string(type);
            }
            if (tree) tree->add("Extension: " + note, o + static_cast<size_t>(p - base) + i, 4 + len);
            i = body + len;
        }
    }

    // One handshake message at [p, p+n) of the record; returns the info word for it
    std::string handshake(Context &ctx, const char *base, const char *p, size_t n, Hello &hello, Field *tree) {
        if (n < 4) return "Handshake";
        const uint8_t type = static_cast<uint8_t>(p[0]);
        const size_t len = (static_cast<size_t>(static_cast<uint8_t>(p[1])) << 16) | be16(p + 2);
        const size_t o = ctx.offsetOf(base) + static_cast<size_t>(p - base);
        std::string name = handshakeName(type);

        Field *hs = nullptr;
        if (tree) {
            hs = &tree->add("Handshake Protocol: " + name, o, std::min(n, len + 4));
            hs->add("Handshake Type: " + name + " (" + std::to_string(type) + ")", o, 1);
            hs->add("Length: " + std::to_string(len), o + 1, 3);
        }
        const size_t avail = std::min(n - 4, len);
        const char *b = p + 4;

        if ((type == 1 || type == 2) && avail >= 35) {
            const bool client = type == 1;
            hello.version = be16(b);
            size_t i = 2 + 32;                                  // version + random
            const size_t sidLen = static_cast<uint8_t>(b[i]);
            i += 1 + sidLen;
            if (hs) {
                hs->add("Version: " + versionName(hello.version) + " (" + hexString(hello.version, 4) + ")", o + 4, 2);
                hs->add("Random", o + 6, 32);
            }
            if (i <= avail) {
                if (client && avail >= i + 2) {
                    const size_t suites = be16(b + i);
                    if (hs) hs->add("Cipher Suites (" + std::to_string(suites / 2) + " suites)", o + 4 + i, 2 + std::min(suites, avail - i - 2));
                    i += 2 + suites;
                    if (i < avail) i += 1 + static_cast<uint8_t>(b[i]);   // compression methods
                } else if (!client && avail >= i + 3) {
                    hello.cipher = be16(b + i);
                    if (hs) hs->add("Cipher Suite: " + cipherName(hello.cipher) + " (" + hexString(hello.cipher, 4) + ")", o + 4 + i, 2);
                    i += 3;                                       // suite + compression method
                }
                if (i + 2 <= avail) {
                    const size_t extLen = be16(b + i);
                    i += 2;
                    Field *ext = hs ? &hs->add("Extensions Length: " + std::to_string(extLen), o + 4 + i - 2, 2) : nullptr;
                    (void)ext;
                    parseExtensions(ctx, base, b + i, std::min(extLen, avail - i), client, hello, hs);
                }
            }
            if (client && !hello.serverName.empty()) name += " (SNI=" + hello.serverName + ")";
        }
        return name;
    }
} // namespace

bool dissect::dissectTls(Context &ctx, const char *data, size_t length) {
    if (!plausibleRecord(data, length)) return false;

    auto &pack = ctx.pack;
    const size_t o = ctx.offsetOf(data);
    pack.protocol = "TLS";
    pack.app_code = static_cast<uint8_t>(data[0]);
    pack.app_flags = be16(data + 1);

    Field *layer = ctx.wantFields() ? &ctx.addLayer("Transport Layer Security", o, length) : nullptr;
    std::string info;
    Hello hello;
    size_t pos = 0;
    int records = 0;
    while (length - pos >= 5 && records < 16) {
        if (!plausibleRecord(data + pos, length - pos)) break;
        const uint8_t type = static_cast<uint8_t>(data[pos]);
        const uint16_t version = be16(data + pos + 1);
        const size_t recLen = be16(data + pos + 3);
        const size_t avail = std::min(recLen, length - pos - 5);
        const bool partial = avail < recLen;

        Field *rec = nullptr;
        if (layer) {
            rec = &layer->add(versionName(version) + " Record Layer: " + contentTypeName(type), o + pos, 5 + avail);
            rec->add(std::string("Content Type: ") + contentTypeName(type) + " (" + std::to_string(type) + ")", o + pos, 1);
            rec->add("Version: " + versionName(version) + " (" + hexString(version, 4) + ")", o + pos + 1, 2);
            rec->add("Length: " + std::to_string(recLen), o + pos + 3, 2);
        }

        std::string part;
        if (type == 22) {
            // one record may hold several handshake messages
            size_t hp = 0;
            int messages = 0;
            while (avail - hp >= 4 && messages < 8) {
                const char *m = data + pos + 5 + hp;
                const size_t mlen = (static_cast<size_t>(static_cast<uint8_t>(m[1])) << 16) | be16(m + 2);
                const std::string w = handshake(ctx, data, m, avail - hp, hello, rec);
                if (pack.app_type == 0) pack.app_type = static_cast<uint8_t>(m[0]);
                part += (part.empty() ? "" : ", ") + w;
                ++messages;
                if (mlen >= avail - hp - 4) break; // the message fills (or overruns) the rest of the record
                hp += 4 + mlen;
            }
            if (part.empty()) part = "Handshake";
            if (hello.cipher != 0) part += " (" + cipherName(hello.cipher) + ")";
        } else if (type == 23) {
            part = "Application Data";
            if (rec) rec->add("Encrypted Application Data (" + std::to_string(avail) + " bytes)", o + pos + 5, avail);
        } else if (type == 21 && avail >= 2) {
            part = "Alert";
            if (rec) rec->add("Alert Message: level " + std::to_string(static_cast<uint8_t>(data[pos + 5])) + ", description " +
                              std::to_string(static_cast<uint8_t>(data[pos + 6])), o + pos + 5, 2);
        } else {
            part = contentTypeName(type);
        }
        if (partial) part += " [fragment]";
        info += (info.empty() ? "" : ", ") + part;

        if (!hello.serverName.empty()) pack.app_text = hello.serverName;
        pos += 5 + recLen;
        ++records;
        if (partial) break;
    }
    pack.info = info.empty() ? "TLS record" : info;
    if (hello.supportedVersion >= 0x0304 || hello.version == 0x0304) pack.protocol = "TLS";
    return true;
}

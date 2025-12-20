// See tls_handshake.h. The decoders here were part of tls.cpp; they are unchanged except that they no longer know where the
// bytes came from, and that the DTLS hello layout (cookie) is understood.
#include "tls_handshake.h"

#include "util.h"
#include "x509.h"

#include <algorithm>
#include <cstring>

using packet::Field;

namespace dissect::tlsparse {
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

    const char *handshakeName(uint8_t t, bool dtls) {
        switch (t) {
            case 0: return "Hello Request";
            case 1: return "Client Hello";
            case 2: return "Server Hello";
            case 3: return dtls ? "Hello Verify Request" : "Handshake message";
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
            case 0xfeff: return "DTLS 1.0";
            case 0xfefd: return "DTLS 1.2";
            case 0xfefc: return "DTLS 1.3";
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

    const char *alertName(uint8_t d) {
        switch (d) {
            case 0: return "close_notify";
            case 10: return "unexpected_message";
            case 20: return "bad_record_mac";
            case 40: return "handshake_failure";
            case 42: return "bad_certificate";
            case 43: return "unsupported_certificate";
            case 44: return "certificate_revoked";
            case 45: return "certificate_expired";
            case 46: return "certificate_unknown";
            case 47: return "illegal_parameter";
            case 48: return "unknown_ca";
            case 49: return "access_denied";
            case 50: return "decode_error";
            case 51: return "decrypt_error";
            case 70: return "protocol_version";
            case 71: return "insufficient_security";
            case 80: return "internal_error";
            case 86: return "inappropriate_fallback";
            case 90: return "user_canceled";
            case 100: return "no_renegotiation";
            case 109: return "missing_extension";
            case 112: return "unrecognized_name";
            case 120: return "no_application_protocol";
            default: return nullptr;
        }
    }

    namespace {
    std::string groupName(uint16_t g) {
        switch (g) {
            case 23: return "secp256r1";
            case 24: return "secp384r1";
            case 25: return "secp521r1";
            case 29: return "x25519";
            case 30: return "x448";
            case 256: return "ffdhe2048";
            case 257: return "ffdhe3072";
            case 4588: return "X25519MLKEM768";
            case 25497: return "X25519Kyber768Draft00";
            default: return (g & 0x0f0f) == 0x0a0a ? "GREASE" : std::to_string(g);
        }
    }

    std::string signatureName(uint16_t a) {
        switch (a) {
            case 0x0401: return "rsa_pkcs1_sha256";
            case 0x0501: return "rsa_pkcs1_sha384";
            case 0x0601: return "rsa_pkcs1_sha512";
            case 0x0201: return "rsa_pkcs1_sha1";
            case 0x0403: return "ecdsa_secp256r1_sha256";
            case 0x0503: return "ecdsa_secp384r1_sha384";
            case 0x0603: return "ecdsa_secp521r1_sha512";
            case 0x0203: return "ecdsa_sha1";
            case 0x0804: return "rsa_pss_rsae_sha256";
            case 0x0805: return "rsa_pss_rsae_sha384";
            case 0x0806: return "rsa_pss_rsae_sha512";
            case 0x0807: return "ed25519";
            case 0x0808: return "ed448";
            case 0x0809: return "rsa_pss_pss_sha256";
            default: return hexString(a, 4);
        }
    }
    } // namespace

    size_t Joined::frame(size_t pos) const {
        size_t best = 0;
        for (size_t i = 0; i < parts.size(); ++i) if (parts[i].first <= pos) best = i;
        return parts.empty() ? 0 : parts[best].second + (pos - parts[best].first);
    }

    size_t Joined::contiguous(size_t pos, size_t length) const {
        size_t end = bytes.size();
        for (size_t i = 0; i < parts.size(); ++i) if (parts[i].first > pos) { end = parts[i].first; break; }
        return std::min(length, end - pos);
    }

    std::string join(const std::vector<std::string> &items, size_t limit) {
        std::string out;
        for (size_t i = 0; i < items.size() && i < limit; ++i) out += (i ? ", " : "") + items[i];
        if (items.size() > limit) out += ", ...";
        return out;
    }

    // Walks the extensions block bytes[at, at+n); fills `h` and (when `tree`) adds nodes
    void parseExtensions(const Joined &j, size_t at, size_t n, bool client, Hello &h, Field *tree) {
        const char *p = j.bytes.data() + at;
        size_t i = 0;
        while (n - i >= 4) {
            const uint16_t type = be16(p + i), len = be16(p + i + 2);
            const size_t body = i + 4;
            if (n - body < len) break;
            const char *d = p + body;
            std::string note;
            std::vector<std::string> details;   // children of the extension node
            if (type == 0 && client && len >= 5) { // server_name: list length(2), name type(1), name length(2), name
                const size_t nameLen = be16(d + 3);
                if (5 + nameLen <= len && d[2] == 0) {
                    h.serverName.assign(d + 5, nameLen);
                    note = "server_name: " + h.serverName;
                    details.push_back("Server Name: " + h.serverName);
                }
            } else if (type == 43) { // supported_versions
                std::vector<std::string> names;
                if (client && len >= 3) {
                    for (size_t k = 1; k + 1 < len; k += 2) {
                        h.supportedVersion = std::max<uint16_t>(h.supportedVersion, be16(d + k));
                        names.push_back(versionName(be16(d + k)));
                    }
                } else if (!client && len == 2) {
                    h.supportedVersion = be16(d);
                    names.push_back(versionName(be16(d)));
                }
                note = "supported_versions";
                if (!names.empty()) details.push_back("Supported Versions: " + join(names));
            } else if (type == 16 && len >= 4) { // ALPN: list length(2), then length-prefixed protocols
                std::string all;
                for (size_t k = 2; k < len;) {
                    const size_t pl = static_cast<uint8_t>(d[k]);
                    if (k + 1 + pl > len) break;
                    if (!all.empty()) all += ", ";
                    all.append(d + k + 1, pl);
                    details.push_back("ALPN Next Protocol: " + std::string(d + k + 1, pl));
                    k += 1 + pl;
                }
                if (h.alpn.empty()) h.alpn = all;
                note = "application_layer_protocol_negotiation: " + all;
            } else if (type == 10 && len >= 2) { // supported_groups
                std::vector<std::string> names;
                for (size_t k = 2; k + 1 < len; k += 2) names.push_back(groupName(be16(d + k)));
                note = "supported_groups";
                details.push_back("Supported Groups: " + join(names));
            } else if (type == 13 && len >= 2) { // signature_algorithms
                std::vector<std::string> names;
                for (size_t k = 2; k + 1 < len; k += 2) names.push_back(signatureName(be16(d + k)));
                note = "signature_algorithms";
                details.push_back("Signature Algorithms: " + join(names));
            } else if (type == 11 && len >= 1) { // ec_point_formats
                note = "ec_point_formats";
                details.push_back("EC point formats length: " + std::to_string(static_cast<uint8_t>(d[0])));
            } else if (type == 51) { // key_share: client list or the server's selected group
                note = "key_share";
                std::vector<std::string> names;
                if (client && len >= 2) {
                    for (size_t k = 2; k + 4 <= len;) {
                        const size_t kl = be16(d + k + 2);
                        names.push_back(groupName(be16(d + k)));
                        k += 4 + kl;
                    }
                } else if (!client && len >= 2) {
                    names.push_back(groupName(be16(d)));
                }
                if (!names.empty()) details.push_back("Key Share Groups: " + join(names));
            } else if (type == 45 && len >= 2) { // psk_key_exchange_modes
                note = "psk_key_exchange_modes";
                for (size_t k = 1; k < len; ++k) details.push_back(std::string("PSK Key Exchange Mode: ") + (d[k] == 1 ? "psk_dhe_ke" : d[k] == 0 ? "psk_ke" : "unknown") + " (" + std::to_string(static_cast<uint8_t>(d[k])) + ")");
            } else if (type == 42) {
                if (client) h.earlyData = true;
                note = "early_data";
            } else if (type == 35) {
                note = "session_ticket";
                details.push_back("Session Ticket: " + std::to_string(len) + " bytes");
            } else if (type == 65281) {
                note = "renegotiation_info";
            } else if (type == 23) {
                note = "extended_master_secret";
            } else if (type == 5) {
                note = "status_request";
            } else {
                note = "extension " + std::to_string(type);
            }
            if (tree) {
                Field &e = tree->add("Extension: " + note, j.frame(at + i), j.contiguous(at + i, 4 + len));
                e.add("Type: " + std::to_string(type), j.frame(at + i), 2);
                e.add("Length: " + std::to_string(len), j.frame(at + i + 2), 2);
                for (const auto &t: details) e.add(t, j.frame(at + body), j.contiguous(at + body, len));
            }
            i = body + len;
        }
    }

    // Certificate message body [at, at+n): TLS 1.2 (list) or TLS 1.3 (request context + list with extensions)
    void parseCertificates(const Joined &j, size_t at, size_t n, Hello &h, Field *tree) {
        const char *b = j.bytes.data() + at;
        size_t i = 0;
        bool v13 = false;
        auto listLenAt = [&](size_t k) { return n - k >= 3 ? (static_cast<size_t>(static_cast<uint8_t>(b[k])) << 16) | be16(b + k + 1) : size_t(0); };
        if (n >= 3 && listLenAt(0) == n - 3) {
            i = 3;
        } else if (n >= 4) {
            const size_t ctxLen = static_cast<uint8_t>(b[0]);
            if (n >= 1 + ctxLen + 3 && listLenAt(1 + ctxLen) == n - 1 - ctxLen - 3) { v13 = true; i = 1 + ctxLen + 3; }
            else i = 3;                                       // damaged or cut: read what is there as a TLS 1.2 list
        } else {
            return;
        }
        int index = 0;
        while (n - i >= 3 && index < 16) {
            const size_t len = (static_cast<size_t>(static_cast<uint8_t>(b[i])) << 16) | be16(b + i + 1);
            const size_t take = std::min(len, n - i - 3);
            const CertificateSummary c = parseCertificate(reinterpret_cast<const unsigned char *>(b + i + 3), take);
            if (c.ok && h.subject.empty()) h.subject = c.commonName;
            if (tree) {
                const std::string title = "Certificate: " + (c.ok ? (c.commonName.empty() ? c.subject : c.commonName) : std::string("(") + std::to_string(len) + " bytes)");
                Field &cert = tree->add(title, j.frame(at + i), j.contiguous(at + i, 3 + take));
                cert.add("Certificate Length: " + std::to_string(len), j.frame(at + i), 3);
                if (c.ok) {
                    cert.add("Subject: " + c.subject, j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                    cert.add("Issuer: " + c.issuer, j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                    cert.add("Serial Number: 0x" + c.serial, j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                    cert.add("Not Before: " + c.notBefore, j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                    cert.add("Not After: " + c.notAfter, j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                    if (!c.dnsNames.empty()) cert.add("Subject Alternative Names: " + join(c.dnsNames, 12), j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                } else {
                    cert.add("[Could not read the certificate]", j.frame(at + i + 3), j.contiguous(at + i + 3, take));
                }
            }
            i += 3 + len;
            if (len > n) break;
            if (v13) {                                        // per-certificate extensions
                if (n - std::min(n, i) < 2) break;
                i += 2 + be16(b + i);
            }
            ++index;
            if (i > n) break;
        }
    }

    std::string decodeHandshakeBody(const Joined &j, uint8_t type, size_t base, size_t avail, bool complete, Hello &hello,
                                    Field *hs, bool dtls) {
        const char *b = j.bytes.data() + base;
        std::string name = handshakeName(type, dtls);

        if ((type == 1 || type == 2) && avail >= 35) {
            const bool client = type == 1;
            hello.version = be16(b);
            size_t i = 2 + 32;                                  // version + random
            const size_t sidLen = static_cast<uint8_t>(b[i]);
            // a handshake record that is really encrypted (a TLS 1.2 Finished) can start with these bytes by chance: only a
            // message that is complete and has a sane version and session id counts as a hello
            const bool versionOk = dtls ? ((hello.version >> 8) == 0xfe && (hello.version == 0xfeff || hello.version == 0xfefd || hello.version == 0xfefc))
                                        : ((hello.version >> 8) == 3 && (hello.version & 0xff) <= 4);
            if (hello.helloType == 0 && complete && versionOk && sidLen <= 32 && 35 + sidLen <= avail) {
                hello.helloType = type;
                std::memcpy(hello.random.data(), b + 2, 32);
            }
            if (hs) {
                hs->add("Version: " + versionName(hello.version) + " (" + hexString(hello.version, 4) + ")", j.frame(base), 2);
                hs->add("Random", j.frame(base + 2), 32);
                if (sidLen > 0 && i + 1 + sidLen <= avail) hs->add("Session ID Length: " + std::to_string(sidLen), j.frame(base + i), 1);
            }
            i += 1 + sidLen;
            if (dtls && client && i < avail) {                  // DTLS ClientHello: cookie<0..2^8-1> after the session id
                const size_t cookieLen = static_cast<uint8_t>(b[i]);
                hello.cookieLength = static_cast<int>(cookieLen);
                if (hs) {
                    hs->add("Cookie Length: " + std::to_string(cookieLen), j.frame(base + i), 1);
                    if (cookieLen > 0 && i + 1 + cookieLen <= avail) hs->add("Cookie", j.frame(base + i + 1), j.contiguous(base + i + 1, cookieLen));
                }
                i += 1 + cookieLen;
            }
            if (i <= avail) {
                if (client && avail >= i + 2) {
                    const size_t suites = be16(b + i);
                    if (hs) {
                        Field &cs = hs->add("Cipher Suites (" + std::to_string(suites / 2) + " suites)", j.frame(base + i), 2 + std::min(suites, avail - i - 2));
                        for (size_t k = 0; k + 1 < suites && i + 2 + k + 2 <= avail && k / 2 < 64; k += 2) {
                            const uint16_t c = be16(b + i + 2 + k);
                            cs.add("Cipher Suite: " + cipherName(c) + " (" + hexString(c, 4) + ")", j.frame(base + i + 2 + k), 2);
                        }
                    }
                    i += 2 + suites;
                    if (i < avail) {
                        if (hs) hs->add("Compression Methods Length: " + std::to_string(static_cast<uint8_t>(b[i])), j.frame(base + i), 1);
                        i += 1 + static_cast<uint8_t>(b[i]);   // compression methods
                    }
                } else if (!client && avail >= i + 3) {
                    hello.cipher = be16(b + i);
                    if (hs) hs->add("Cipher Suite: " + cipherName(hello.cipher) + " (" + hexString(hello.cipher, 4) + ")", j.frame(base + i), 2);
                    i += 3;                                       // suite + compression method
                }
                if (i + 2 <= avail) {
                    const size_t extLen = be16(b + i);
                    i += 2;
                    if (hs) hs->add("Extensions Length: " + std::to_string(extLen), j.frame(base + i - 2), 2);
                    parseExtensions(j, base + i, std::min(extLen, avail - i), client, hello, hs);
                }
            }
            if (client && !hello.serverName.empty()) name += " (SNI=" + hello.serverName + ")";
        } else if (type == 3 && dtls && avail >= 3) {            // HelloVerifyRequest: server_version, cookie<0..2^8-1>
            const size_t cookieLen = static_cast<uint8_t>(b[2]);
            hello.cookieLength = static_cast<int>(cookieLen);
            if (hs) {
                hs->add("Version: " + versionName(be16(b)) + " (" + hexString(be16(b), 4) + ")", j.frame(base), 2);
                hs->add("Cookie Length: " + std::to_string(cookieLen), j.frame(base + 2), 1);
                if (cookieLen > 0 && 3 + cookieLen <= avail) hs->add("Cookie", j.frame(base + 3), j.contiguous(base + 3, cookieLen));
            }
        } else if (type == 11) {
            parseCertificates(j, base, avail, hello, hs);
        } else if (type == 4 && avail >= 4 && hs) {
            hs->add("Session Ticket Lifetime Hint: " + std::to_string(be32(b)) + " seconds", j.frame(base), 4);
        }
        return name;
    }
} // namespace dissect::tlsparse

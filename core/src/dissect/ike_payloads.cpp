// IKEv2 / IKEv1 payload chains (see ike_payloads.h). Oracles: RFC 7296 (3.2 - 3.16, IANA registries 3.3.2 - 3.3.5, 3.6, 3.10.1,
// 3.12), RFC 7383 (SKF), RFC 2408 (3), RFC 2409 (appendix A), RFC 2407 (4). Name tables were written from these documents and the
// IANA registries from memory, without network access; an unknown value is shown as its number.
#include "ike_payloads.h"

#include <algorithm>
#include <vector>

#include "util.h"
#include <network/byteorder.h>

using packet::Field;

namespace {
    using namespace dissect;

    // ---- bounded access ---------------------------------------------------------------------------------------------------------
    // A view of bytes that all lie inside the frame, with the frame offset of the first one. Reads past the end give 0 and `has`
    // says whether a field fits; nodes added through a view are clamped to it.
    struct View {
        const uint8_t *p = nullptr;
        size_t n = 0;
        size_t off = 0;

        bool has(size_t at, size_t len) const { return at <= n && len <= n - at; }
        uint8_t u8(size_t at) const { return at < n ? p[at] : 0; }
        uint16_t u16(size_t at) const { return has(at, 2) ? static_cast<uint16_t>((p[at] << 8) | p[at + 1]) : 0; }
        uint32_t u32(size_t at) const { return has(at, 4) ? (static_cast<uint32_t>(p[at]) << 24) | (static_cast<uint32_t>(p[at + 1]) << 16) | (static_cast<uint32_t>(p[at + 2]) << 8) | p[at + 3] : 0; }
        View sub(size_t at, size_t len) const {
            View v;
            if (at > n) return v;
            v.p = p + at;
            v.n = std::min(len, n - at);
            v.off = off + at;
            return v;
        }
        View from(size_t at) const { return sub(at, n > at ? n - at : 0); }
    };

    // The tree being built; a null node (summary pass) swallows everything.
    struct Tree {
        Field *f = nullptr;
        explicit operator bool() const { return f != nullptr; }
        Tree add(const View &v, size_t at, size_t len, std::string text) const {
            if (!f) return {};
            const size_t start = std::min(at, v.n);
            return {&f->add(std::move(text), v.off + start, std::min(len, v.n - start))};
        }
        Tree note(std::string text) const { return f ? Tree{&f->add(std::move(text), 0, 0)} : Tree{}; }
    };

    std::string bytesHex(const View &v, size_t at, size_t len, size_t limit = 32) {
        static const char digits[] = "0123456789abcdef";
        std::string out;
        const size_t take = std::min({len, limit, v.n > at ? v.n - at : 0});
        for (size_t i = 0; i < take; ++i) {
            out += digits[v.p[at + i] >> 4];
            out += digits[v.p[at + i] & 15];
        }
        if (take < len) out += "...";
        return out;
    }

    bool printable(const View &v, size_t at, size_t len) {
        if (len == 0 || !v.has(at, len)) return false;
        for (size_t i = 0; i < len; ++i) if (v.p[at + i] < 0x20 || v.p[at + i] > 0x7e) return false;
        return true;
    }

    std::string text(const View &v, size_t at, size_t len) {
        return v.has(at, len) ? std::string(reinterpret_cast<const char *>(v.p + at), len) : std::string();
    }

    std::string withNumber(const std::string &name, unsigned long long value) { return name + " (" + std::to_string(value) + ")"; }

    std::string ipText(const View &v, size_t at, size_t len) {
        if (len == 4 && v.has(at, 4)) return network::formatIPv4(v.p + at);
        if (len == 16 && v.has(at, 16)) return network::formatIPv6(v.p + at);
        return {};
    }

    std::string ipProtocolText(uint8_t p) {
        switch (p) {
            case 0: return "any (0)";
            case 1: return "ICMP (1)";
            case 6: return "TCP (6)";
            case 17: return "UDP (17)";
            case 47: return "GRE (47)";
            case 50: return "ESP (50)";
            case 51: return "AH (51)";
            case 58: return "ICMPv6 (58)";
            case 132: return "SCTP (132)";
            default: return std::to_string(p);
        }
    }

    // ---- registries --------------------------------------------------------------------------------------------------------------
    std::string protocolIdName(uint8_t id) {   // RFC 7296 3.3.1 (IKEv2) / RFC 2407 4.4.1 (IKEv1 DOI)
        switch (id) {
            case 1: return "IKE";
            case 2: return "AH";
            case 3: return "ESP";
            case 4: return "FC_ESP_HEADER / IPCOMP";
            case 5: return "FC_CT_AUTHENTICATION";
            default: return "Protocol " + std::to_string(id);
        }
    }

    std::string v2TransformTypeName(uint8_t type) {
        switch (type) {
            case 1: return "Encryption Algorithm (ENCR)";
            case 2: return "Pseudorandom Function (PRF)";
            case 3: return "Integrity Algorithm (INTEG)";
            case 4: return "Key Exchange Method / Diffie-Hellman Group (D-H)";
            case 5: return "Extended Sequence Numbers (ESN)";
            default: return "Transform Type " + std::to_string(type);
        }
    }

    std::string dhGroupName(unsigned id) {   // IANA "Transform Type 4" / IKEv1 Oakley group descriptions
        switch (id) {
            case 0: return "NONE";
            case 1: return "768-bit MODP Group";
            case 2: return "1024-bit MODP Group";
            case 5: return "1536-bit MODP Group";
            case 14: return "2048-bit MODP Group";
            case 15: return "3072-bit MODP Group";
            case 16: return "4096-bit MODP Group";
            case 17: return "6144-bit MODP Group";
            case 18: return "8192-bit MODP Group";
            case 19: return "256-bit random ECP Group";
            case 20: return "384-bit random ECP Group";
            case 21: return "521-bit random ECP Group";
            case 22: return "1024-bit MODP Group with 160-bit Prime Order Subgroup";
            case 23: return "2048-bit MODP Group with 224-bit Prime Order Subgroup";
            case 24: return "2048-bit MODP Group with 256-bit Prime Order Subgroup";
            case 25: return "192-bit Random ECP Group";
            case 26: return "224-bit Random ECP Group";
            case 27: return "brainpoolP224r1";
            case 28: return "brainpoolP256r1";
            case 29: return "brainpoolP384r1";
            case 30: return "brainpoolP512r1";
            case 31: return "Curve25519";
            case 32: return "Curve448";
            default: return "Group " + std::to_string(id);
        }
    }

    std::string v2TransformIdName(uint8_t type, unsigned id) {
        switch (type) {
            case 1:
                switch (id) {
                    case 1: return "ENCR_DES_IV64";
                    case 2: return "ENCR_DES";
                    case 3: return "ENCR_3DES";
                    case 4: return "ENCR_RC5";
                    case 5: return "ENCR_IDEA";
                    case 6: return "ENCR_CAST";
                    case 7: return "ENCR_BLOWFISH";
                    case 8: return "ENCR_3IDEA";
                    case 9: return "ENCR_DES_IV32";
                    case 11: return "ENCR_NULL";
                    case 12: return "ENCR_AES_CBC";
                    case 13: return "ENCR_AES_CTR";
                    case 14: return "ENCR_AES_CCM_8";
                    case 15: return "ENCR_AES_CCM_12";
                    case 16: return "ENCR_AES_CCM_16";
                    case 18: return "ENCR_AES_GCM_8";
                    case 19: return "ENCR_AES_GCM_12";
                    case 20: return "ENCR_AES_GCM_16";
                    case 21: return "ENCR_NULL_AUTH_AES_GMAC";
                    case 23: return "ENCR_CAMELLIA_CBC";
                    case 24: return "ENCR_CAMELLIA_CTR";
                    case 25: return "ENCR_CAMELLIA_CCM_8";
                    case 26: return "ENCR_CAMELLIA_CCM_12";
                    case 27: return "ENCR_CAMELLIA_CCM_16";
                    case 28: return "ENCR_CHACHA20_POLY1305";
                    default: break;
                }
                break;
            case 2:
                switch (id) {
                    case 1: return "PRF_HMAC_MD5";
                    case 2: return "PRF_HMAC_SHA1";
                    case 3: return "PRF_HMAC_TIGER";
                    case 4: return "PRF_AES128_XCBC";
                    case 5: return "PRF_HMAC_SHA2_256";
                    case 6: return "PRF_HMAC_SHA2_384";
                    case 7: return "PRF_HMAC_SHA2_512";
                    case 8: return "PRF_AES128_CMAC";
                    default: break;
                }
                break;
            case 3:
                switch (id) {
                    case 0: return "NONE";
                    case 1: return "AUTH_HMAC_MD5_96";
                    case 2: return "AUTH_HMAC_SHA1_96";
                    case 3: return "AUTH_DES_MAC";
                    case 4: return "AUTH_KPDK_MD5";
                    case 5: return "AUTH_AES_XCBC_96";
                    case 6: return "AUTH_HMAC_MD5_128";
                    case 7: return "AUTH_HMAC_SHA1_160";
                    case 8: return "AUTH_AES_CMAC_96";
                    case 9: return "AUTH_AES_128_GMAC";
                    case 10: return "AUTH_AES_192_GMAC";
                    case 11: return "AUTH_AES_256_GMAC";
                    case 12: return "AUTH_HMAC_SHA2_256_128";
                    case 13: return "AUTH_HMAC_SHA2_384_192";
                    case 14: return "AUTH_HMAC_SHA2_512_256";
                    default: break;
                }
                break;
            case 4: return dhGroupName(id);
            case 5:
                if (id == 0) return "No Extended Sequence Numbers";
                if (id == 1) return "Extended Sequence Numbers";
                break;
            default: break;
        }
        return "ID " + std::to_string(id);
    }

    std::string idTypeV2(uint8_t type) {   // RFC 7296 3.5
        switch (type) {
            case 1: return "ID_IPV4_ADDR";
            case 2: return "ID_FQDN";
            case 3: return "ID_RFC822_ADDR";
            case 5: return "ID_IPV6_ADDR";
            case 9: return "ID_DER_ASN1_DN";
            case 10: return "ID_DER_ASN1_GN";
            case 11: return "ID_KEY_ID";
            case 12: return "ID_FC_NAME";
            case 13: return "ID_NULL";
            default: return "ID type " + std::to_string(type);
        }
    }

    std::string idTypeV1(uint8_t type) {   // RFC 2407 4.6.2.1
        switch (type) {
            case 1: return "ID_IPV4_ADDR";
            case 2: return "ID_FQDN";
            case 3: return "ID_USER_FQDN";
            case 4: return "ID_IPV4_ADDR_SUBNET";
            case 5: return "ID_IPV6_ADDR";
            case 6: return "ID_IPV6_ADDR_SUBNET";
            case 7: return "ID_IPV4_ADDR_RANGE";
            case 8: return "ID_IPV6_ADDR_RANGE";
            case 9: return "ID_DER_ASN1_DN";
            case 10: return "ID_DER_ASN1_GN";
            case 11: return "ID_KEY_ID";
            default: return "ID type " + std::to_string(type);
        }
    }

    std::string certEncodingV2(uint8_t e) {   // RFC 7296 3.6
        switch (e) {
            case 1: return "PKCS #7 wrapped X.509 certificate";
            case 2: return "PGP Certificate";
            case 3: return "DNS Signed Key";
            case 4: return "X.509 Certificate - Signature";
            case 6: return "Kerberos Token";
            case 7: return "Certificate Revocation List (CRL)";
            case 8: return "Authority Revocation List (ARL)";
            case 9: return "SPKI Certificate";
            case 10: return "X.509 Certificate - Attribute";
            case 11: return "Raw RSA Key";
            case 12: return "Hash and URL of X.509 certificate";
            case 13: return "Hash and URL of X.509 bundle";
            case 14: return "OCSP Content";
            default: return "Certificate encoding " + std::to_string(e);
        }
    }

    std::string certEncodingV1(uint8_t e) {   // RFC 2408 3.9
        switch (e) {
            case 0: return "NONE";
            case 1: return "PKCS #7 wrapped X.509 certificate";
            case 2: return "PGP Certificate";
            case 3: return "DNS Signed Key";
            case 4: return "X.509 Certificate - Signature";
            case 5: return "X.509 Certificate - Key Exchange";
            case 6: return "Kerberos Tokens";
            case 7: return "Certificate Revocation List (CRL)";
            case 8: return "Authority Revocation List (ARL)";
            case 9: return "SPKI Certificate";
            case 10: return "X.509 Certificate - Attribute";
            default: return "Certificate encoding " + std::to_string(e);
        }
    }

    std::string authMethodV2(uint8_t m) {   // RFC 7296 3.8, RFC 4754, RFC 5998, RFC 7427
        switch (m) {
            case 1: return "RSA Digital Signature";
            case 2: return "Shared Key Message Integrity Code";
            case 3: return "DSS Digital Signature";
            case 9: return "ECDSA with SHA-256 on the P-256 curve";
            case 10: return "ECDSA with SHA-384 on the P-384 curve";
            case 11: return "ECDSA with SHA-512 on the P-521 curve";
            case 12: return "Generic Secure Password Authentication Method";
            case 13: return "NULL Authentication";
            case 14: return "Digital Signature";
            default: return "Authentication method " + std::to_string(m);
        }
    }

    std::string configTypeName(uint8_t t) {
        switch (t) {
            case 1: return "CFG_REQUEST";
            case 2: return "CFG_REPLY";
            case 3: return "CFG_SET";
            case 4: return "CFG_ACK";
            default: return "Configuration type " + std::to_string(t);
        }
    }

    std::string configAttributeName(unsigned t) {   // RFC 7296 3.15.1
        switch (t) {
            case 1: return "INTERNAL_IP4_ADDRESS";
            case 2: return "INTERNAL_IP4_NETMASK";
            case 3: return "INTERNAL_IP4_DNS";
            case 4: return "INTERNAL_IP4_NBNS";
            case 5: return "INTERNAL_ADDRESS_EXPIRY";
            case 6: return "INTERNAL_IP4_DHCP";
            case 7: return "APPLICATION_VERSION";
            case 8: return "INTERNAL_IP6_ADDRESS";
            case 10: return "INTERNAL_IP6_DNS";
            case 12: return "INTERNAL_IP6_DHCP";
            case 13: return "INTERNAL_IP4_SUBNET";
            case 14: return "SUPPORTED_ATTRIBUTES";
            case 15: return "INTERNAL_IP6_SUBNET";
            default: return "Attribute " + std::to_string(t);
        }
    }

    std::string eapCodeName(uint8_t c) {
        switch (c) {
            case 1: return "Request";
            case 2: return "Response";
            case 3: return "Success";
            case 4: return "Failure";
            default: return "Code " + std::to_string(c);
        }
    }

    std::string notifyNameV1(uint16_t t) {   // RFC 2408 3.14.1 and RFC 2407 4.6.3
        switch (t) {
            case 1: return "INVALID-PAYLOAD-TYPE";
            case 2: return "DOI-NOT-SUPPORTED";
            case 3: return "SITUATION-NOT-SUPPORTED";
            case 4: return "INVALID-COOKIE";
            case 5: return "INVALID-MAJOR-VERSION";
            case 6: return "INVALID-MINOR-VERSION";
            case 7: return "INVALID-EXCHANGE-TYPE";
            case 8: return "INVALID-FLAGS";
            case 9: return "INVALID-MESSAGE-ID";
            case 10: return "INVALID-PROTOCOL-ID";
            case 11: return "INVALID-SPI";
            case 12: return "INVALID-TRANSFORM-ID";
            case 13: return "ATTRIBUTES-NOT-SUPPORTED";
            case 14: return "NO-PROPOSAL-CHOSEN";
            case 15: return "BAD-PROPOSAL-SYNTAX";
            case 16: return "PAYLOAD-MALFORMED";
            case 17: return "INVALID-KEY-INFORMATION";
            case 18: return "INVALID-ID-INFORMATION";
            case 19: return "INVALID-CERT-ENCODING";
            case 20: return "INVALID-CERTIFICATE";
            case 21: return "CERT-TYPE-UNSUPPORTED";
            case 22: return "INVALID-CERT-AUTHORITY";
            case 23: return "INVALID-HASH-INFORMATION";
            case 24: return "AUTHENTICATION-FAILED";
            case 25: return "INVALID-SIGNATURE";
            case 26: return "ADDRESS-NOTIFICATION";
            case 27: return "NOTIFY-SA-LIFETIME";
            case 28: return "CERTIFICATE-UNAVAILABLE";
            case 29: return "UNSUPPORTED-EXCHANGE-TYPE";
            case 30: return "UNEQUAL-PAYLOAD-LENGTHS";
            case 16384: return "CONNECTED";
            case 24576: return "RESPONDER-LIFETIME";
            case 24577: return "REPLAY-STATUS";
            case 24578: return "INITIAL-CONTACT";
            default: return "Notify " + std::to_string(t);
        }
    }

    // ---- IKEv1 Security Association attributes (RFC 2409 appendix A, RFC 2407 4.5) ------------------------------------------------
    std::string v1AttributeName(bool isakmp, unsigned type) {
        if (isakmp) {
            switch (type) {
                case 1: return "Encryption-Algorithm";
                case 2: return "Hash-Algorithm";
                case 3: return "Authentication-Method";
                case 4: return "Group-Description";
                case 5: return "Group-Type";
                case 6: return "Group-Prime/Irreducible-Polynomial";
                case 7: return "Group-Generator-One";
                case 8: return "Group-Generator-Two";
                case 9: return "Group-Curve-A";
                case 10: return "Group-Curve-B";
                case 11: return "Life-Type";
                case 12: return "Life-Duration";
                case 13: return "PRF";
                case 14: return "Key-Length";
                case 15: return "Field-Size";
                case 16: return "Group-Order";
                default: break;
            }
        } else {
            switch (type) {
                case 1: return "SA-Life-Type";
                case 2: return "SA-Life-Duration";
                case 3: return "Group-Description";
                case 4: return "Encapsulation-Mode";
                case 5: return "Authentication-Algorithm";
                case 6: return "Key-Length";
                case 7: return "Key-Rounds";
                case 8: return "Compress-Dictionary-Size";
                case 9: return "Compress-Private-Algorithm";
                case 10: return "ECN-Tunnel";
                default: break;
            }
        }
        return "Attribute " + std::to_string(type);
    }

    std::string v1AttributeValue(bool isakmp, unsigned type, unsigned value) {
        std::string name;
        if (isakmp) {
            switch (type) {
                case 1:
                    switch (value) {
                        case 1: name = "DES-CBC"; break;
                        case 2: name = "IDEA-CBC"; break;
                        case 3: name = "Blowfish-CBC"; break;
                        case 4: name = "RC5-R16-B64-CBC"; break;
                        case 5: name = "3DES-CBC"; break;
                        case 6: name = "CAST-CBC"; break;
                        case 7: name = "AES-CBC"; break;
                        case 8: name = "Camellia-CBC"; break;
                        default: break;
                    }
                    break;
                case 2:
                    switch (value) {
                        case 1: name = "MD5"; break;
                        case 2: name = "SHA"; break;
                        case 3: name = "Tiger"; break;
                        case 4: name = "SHA2-256"; break;
                        case 5: name = "SHA2-384"; break;
                        case 6: name = "SHA2-512"; break;
                        default: break;
                    }
                    break;
                case 3:
                    switch (value) {
                        case 1: name = "Pre-shared key"; break;
                        case 2: name = "DSS signatures"; break;
                        case 3: name = "RSA signatures"; break;
                        case 4: name = "Encryption with RSA"; break;
                        case 5: name = "Revised encryption with RSA"; break;
                        case 9: name = "ECDSA with SHA-256 on the P-256 curve"; break;
                        case 10: name = "ECDSA with SHA-384 on the P-384 curve"; break;
                        case 11: name = "ECDSA with SHA-512 on the P-521 curve"; break;
                        case 64221: name = "Hybrid mode, initiator RSA"; break;
                        case 64222: name = "Hybrid mode, responder RSA"; break;
                        case 65001: name = "XAUTH with pre-shared key, initiator"; break;
                        case 65002: name = "XAUTH with pre-shared key, responder"; break;
                        case 65003: name = "XAUTH with DSS, initiator"; break;
                        case 65004: name = "XAUTH with DSS, responder"; break;
                        case 65005: name = "XAUTH with RSA, initiator"; break;
                        case 65006: name = "XAUTH with RSA, responder"; break;
                        default: break;
                    }
                    break;
                case 4: name = dhGroupName(value); break;
                case 11:
                    if (value == 1) name = "Seconds";
                    else if (value == 2) name = "Kilobytes";
                    break;
                default: break;
            }
        } else {
            switch (type) {
                case 1:
                    if (value == 1) name = "Seconds";
                    else if (value == 2) name = "Kilobytes";
                    break;
                case 3: name = dhGroupName(value); break;
                case 4:
                    switch (value) {
                        case 1: name = "Tunnel"; break;
                        case 2: name = "Transport"; break;
                        case 3: name = "UDP-Encapsulated-Tunnel"; break;
                        case 4: name = "UDP-Encapsulated-Transport"; break;
                        default: break;
                    }
                    break;
                case 5:
                    switch (value) {
                        case 1: name = "HMAC-MD5"; break;
                        case 2: name = "HMAC-SHA"; break;
                        case 3: name = "DES-MAC"; break;
                        case 4: name = "KPDK"; break;
                        case 5: name = "HMAC-SHA2-256"; break;
                        case 6: name = "HMAC-SHA2-384"; break;
                        case 7: name = "HMAC-SHA2-512"; break;
                        default: break;
                    }
                    break;
                default: break;
            }
        }
        return name.empty() ? std::to_string(value) : name + " (" + std::to_string(value) + ")";
    }

    std::string v1TransformIdName(uint8_t protocol, unsigned id) {
        switch (protocol) {
            case 1: return id == 1 ? "KEY_IKE" : "ISAKMP transform " + std::to_string(id);
            case 2:   // AH
                switch (id) {
                    case 2: return "AH_MD5";
                    case 3: return "AH_SHA";
                    case 4: return "AH_DES";
                    case 5: return "AH_SHA2-256";
                    case 6: return "AH_SHA2-384";
                    case 7: return "AH_SHA2-512";
                    default: break;
                }
                break;
            case 3:   // ESP
                switch (id) {
                    case 1: return "ESP_DES_IV64";
                    case 2: return "ESP_DES";
                    case 3: return "ESP_3DES";
                    case 4: return "ESP_RC5";
                    case 5: return "ESP_IDEA";
                    case 6: return "ESP_CAST";
                    case 7: return "ESP_BLOWFISH";
                    case 8: return "ESP_3IDEA";
                    case 9: return "ESP_DES_IV32";
                    case 10: return "ESP_RC4";
                    case 11: return "ESP_NULL";
                    case 12: return "ESP_AES";
                    default: break;
                }
                break;
            case 4:   // IPCOMP
                switch (id) {
                    case 1: return "IPCOMP_OUI";
                    case 2: return "IPCOMP_DEFLATE";
                    case 3: return "IPCOMP_LZS";
                    default: break;
                }
                break;
            default: break;
        }
        return "Transform ID " + std::to_string(id);
    }

    // Well-known vendor IDs: the MD5 of the identifying string (RFC 3947 / the NAT-T drafts) or a fixed value (RFC 3706, XAUTH)
    std::string vendorName(const View &v, size_t at, size_t len) {
        struct Known { const char *hex; const char *name; };
        static const Known known[] = {
            {"4a131c81070358455c5728f20e95452f", "RFC 3947 Negotiation of NAT-Traversal in the IKE"},
            {"90cb80913ebb696e086381b5ec427b1f", "draft-ietf-ipsec-nat-t-ike-02\\n"},
            {"7d9419a65310ca6f2c179d9215529d56", "draft-ietf-ipsec-nat-t-ike-03"},
            {"afcad71368a1f1c96b8696fc77570100", "RFC 3706 DPD (Dead Peer Detection)"},
            {"09002689dfd6b712", "XAUTH"},
        };
        const std::string hex = bytesHex(v, at, len, 64);
        for (const auto &k: known) if (hex == k.hex) return k.name;
        return {};
    }

    // ---- notify (IKEv2) -----------------------------------------------------------------------------------------------------------
} // namespace

std::string dissect::ikeV2NotifyName(uint16_t t) {   // RFC 7296 3.10.1 and the IANA "IKEv2 Notify Message Types" registry
    switch (t) {
        case 1: return "UNSUPPORTED_CRITICAL_PAYLOAD";
        case 4: return "INVALID_IKE_SPI";
        case 5: return "INVALID_MAJOR_VERSION";
        case 7: return "INVALID_SYNTAX";
        case 9: return "INVALID_MESSAGE_ID";
        case 11: return "INVALID_SPI";
        case 14: return "NO_PROPOSAL_CHOSEN";
        case 17: return "INVALID_KE_PAYLOAD";
        case 24: return "AUTHENTICATION_FAILED";
        case 34: return "SINGLE_PAIR_REQUIRED";
        case 35: return "NO_ADDITIONAL_SAS";
        case 36: return "INTERNAL_ADDRESS_FAILURE";
        case 37: return "FAILED_CP_REQUIRED";
        case 38: return "TS_UNACCEPTABLE";
        case 39: return "INVALID_SELECTORS";
        case 40: return "UNACCEPTABLE_ADDRESSES";
        case 41: return "UNEXPECTED_NAT_DETECTED";
        case 42: return "USE_ASSIGNED_HoA";
        case 43: return "TEMPORARY_FAILURE";
        case 44: return "CHILD_SA_NOT_FOUND";
        case 45: return "INVALID_GROUP_ID";
        case 46: return "AUTHORIZATION_FAILED";
        case 16384: return "INITIAL_CONTACT";
        case 16385: return "SET_WINDOW_SIZE";
        case 16386: return "ADDITIONAL_TS_POSSIBLE";
        case 16387: return "IPCOMP_SUPPORTED";
        case 16388: return "NAT_DETECTION_SOURCE_IP";
        case 16389: return "NAT_DETECTION_DESTINATION_IP";
        case 16390: return "COOKIE";
        case 16391: return "USE_TRANSPORT_MODE";
        case 16392: return "HTTP_CERT_LOOKUP_SUPPORTED";
        case 16393: return "REKEY_SA";
        case 16394: return "ESP_TFC_PADDING_NOT_SUPPORTED";
        case 16395: return "NON_FIRST_FRAGMENTS_ALSO";
        case 16396: return "MOBIKE_SUPPORTED";
        case 16397: return "ADDITIONAL_IP4_ADDRESS";
        case 16398: return "ADDITIONAL_IP6_ADDRESS";
        case 16399: return "NO_ADDITIONAL_ADDRESSES";
        case 16400: return "UPDATE_SA_ADDRESSES";
        case 16401: return "COOKIE2";
        case 16402: return "NO_NATS_ALLOWED";
        case 16403: return "AUTH_LIFETIME";
        case 16404: return "MULTIPLE_AUTH_SUPPORTED";
        case 16405: return "ANOTHER_AUTH_FOLLOWS";
        case 16406: return "REDIRECT_SUPPORTED";
        case 16407: return "REDIRECT";
        case 16408: return "REDIRECTED_FROM";
        case 16417: return "EAP_ONLY_AUTHENTICATION";
        case 16430: return "IKEV2_FRAGMENTATION_SUPPORTED";
        case 16431: return "SIGNATURE_HASH_ALGORITHMS";
        default: return "Notify " + std::to_string(t);
    }
}

std::string dissect::ikePayloadTypeName(uint8_t version, uint8_t nextPayload) {
    if (nextPayload == 0) return "NONE";
    if (version == 2) {   // RFC 7296 section 3.2 (SKF: RFC 7383)
        switch (nextPayload) {
            case 33: return "Security Association (SA)";
            case 34: return "Key Exchange (KE)";
            case 35: return "Identification - Initiator (IDi)";
            case 36: return "Identification - Responder (IDr)";
            case 37: return "Certificate (CERT)";
            case 38: return "Certificate Request (CERTREQ)";
            case 39: return "Authentication (AUTH)";
            case 40: return "Nonce (Ni, Nr)";
            case 41: return "Notify (N)";
            case 42: return "Delete (D)";
            case 43: return "Vendor ID (V)";
            case 44: return "Traffic Selector - Initiator (TSi)";
            case 45: return "Traffic Selector - Responder (TSr)";
            case 46: return "Encrypted and Authenticated (SK)";
            case 47: return "Configuration (CP)";
            case 48: return "Extensible Authentication (EAP)";
            case 53: return "Encrypted Fragment (SKF)";
            default: return "Payload " + std::to_string(nextPayload);
        }
    }
    switch (nextPayload) {   // RFC 2408 section 3.1, RFC 3947 for NAT-D / NAT-OA
        case 1: return "Security Association (SA)";
        case 2: return "Proposal (P)";
        case 3: return "Transform (T)";
        case 4: return "Key Exchange (KE)";
        case 5: return "Identification (ID)";
        case 6: return "Certificate (CERT)";
        case 7: return "Certificate Request (CR)";
        case 8: return "Hash (HASH)";
        case 9: return "Signature (SIG)";
        case 10: return "Nonce (NONCE)";
        case 11: return "Notification (N)";
        case 12: return "Delete (D)";
        case 13: return "Vendor ID (VID)";
        case 20: return "NAT Discovery (NAT-D)";
        case 21: return "NAT Original Address (NAT-OA)";
        default: return "Payload " + std::to_string(nextPayload);
    }
}

namespace {
    // ---- IKEv2 payload bodies -----------------------------------------------------------------------------------------------------
    // `pl` is the whole payload (generic header included), shown bytes only; bodies start at offset 4.

    void v2Attributes(const View &t, size_t at, const Tree &parent) {   // transform attributes (RFC 7296 3.3.5)
        size_t i = at;
        int guard = 0;
        while (t.has(i, 4) && guard++ < 32) {
            const uint16_t word = t.u16(i);
            const bool tv = word & 0x8000;
            const unsigned type = word & 0x7fff;
            const uint16_t value = t.u16(i + 2);
            const size_t size = tv ? 4 : 4 + value;
            if (!tv && !t.has(i, size)) { parent.add(t, i, t.n - i, "[Attribute extends beyond the transform]"); return; }
            if (type == 14 && tv) parent.add(t, i, 4, "Key Length: " + std::to_string(value) + " bits");
            else parent.add(t, i, size, "Attribute " + std::to_string(type) + (tv ? ": " + std::to_string(value) : " (" + std::to_string(value) + " bytes)"));
            i += size;
        }
    }

    void v2Sa(const View &pl, const Tree &tree) {
        size_t at = 4;
        int proposals = 0;
        while (pl.has(at, 8) && proposals++ < 64) {
            const uint8_t last = pl.u8(at);
            const uint16_t length = pl.u16(at + 2);
            if (length < 8 || !pl.has(at, length)) { tree.add(pl, at, pl.n - at, "[Proposal length " + std::to_string(length) + " is invalid]"); return; }
            const View prop = pl.sub(at, length);
            const uint8_t number = prop.u8(4), protocol = prop.u8(5), spiSize = prop.u8(6), transforms = prop.u8(7);
            Tree p = tree.add(pl, at, length, "Proposal " + std::to_string(number) + ": " + protocolIdName(protocol) + ", " + std::to_string(transforms) + " transform(s)");
            p.add(prop, 0, 1, std::string("Last Substructure: ") + (last == 0 ? "last proposal (0)" : last == 2 ? "more proposals (2)" : std::to_string(last)));
            p.add(prop, 2, 2, "Proposal Length: " + std::to_string(length));
            p.add(prop, 4, 1, "Proposal Number: " + std::to_string(number));
            p.add(prop, 5, 1, "Protocol ID: " + withNumber(protocolIdName(protocol), protocol));
            p.add(prop, 6, 1, "SPI Size: " + std::to_string(spiSize));
            p.add(prop, 7, 1, "Number of Transforms: " + std::to_string(transforms));
            size_t pos = 8;
            if (spiSize) {
                if (!prop.has(pos, spiSize)) { p.add(prop, pos, prop.n - pos, "[SPI extends beyond the proposal]"); at += length; continue; }
                p.add(prop, pos, spiSize, "SPI: " + bytesHex(prop, pos, spiSize));
                pos += spiSize;
            }
            int shown = 0;
            while (prop.has(pos, 8) && shown++ < 64) {
                const uint8_t tlast = prop.u8(pos);
                const uint16_t tlen = prop.u16(pos + 2);
                if (tlen < 8 || !prop.has(pos, tlen)) { p.add(prop, pos, prop.n - pos, "[Transform length " + std::to_string(tlen) + " is invalid]"); break; }
                const View tr = prop.sub(pos, tlen);
                const uint8_t type = tr.u8(4);
                const uint16_t id = tr.u16(6);
                Tree t = p.add(prop, pos, tlen, v2TransformTypeName(type) + ": " + v2TransformIdName(type, id));
                t.add(tr, 0, 1, std::string("Last Substructure: ") + (tlast == 0 ? "last transform (0)" : tlast == 3 ? "more transforms (3)" : std::to_string(tlast)));
                t.add(tr, 2, 2, "Transform Length: " + std::to_string(tlen));
                t.add(tr, 4, 1, "Transform Type: " + withNumber(v2TransformTypeName(type), type));
                t.add(tr, 6, 2, "Transform ID: " + withNumber(v2TransformIdName(type, id), id));
                v2Attributes(tr, 8, t);
                pos += tlen;
            }
            at += length;
            if (last == 0) break;
        }
    }

    void v2Ke(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Key Exchange payload truncated]"); return; }
        const uint16_t group = pl.u16(4);
        tree.add(pl, 4, 2, "Diffie-Hellman Group: " + withNumber(dhGroupName(group), group));
        tree.add(pl, 8, pl.n - 8, "Key Exchange Data (" + std::to_string(pl.n - 8) + " bytes)");
    }

    void v2Id(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Identification payload truncated]"); return; }
        const uint8_t type = pl.u8(4);
        const size_t len = pl.n - 8;
        tree.add(pl, 4, 1, "ID Type: " + withNumber(idTypeV2(type), type));
        std::string value;
        switch (type) {
            case 1: case 5: value = ipText(pl, 8, len); break;
            case 2: case 3: value = printable(pl, 8, len) ? text(pl, 8, len) : std::string(); break;
            case 11: value = bytesHex(pl, 8, len); break;
            default: break;
        }
        tree.add(pl, 8, len, "Identification Data" + (value.empty() ? " (" + std::to_string(len) + " bytes)" : ": " + value));
    }

    void v2Cert(const View &pl, const Tree &tree, bool request) {
        if (!pl.has(4, 1)) { tree.add(pl, 4, pl.n - 4, "[Certificate payload truncated]"); return; }
        const uint8_t enc = pl.u8(4);
        tree.add(pl, 4, 1, "Certificate Encoding: " + withNumber(certEncodingV2(enc), enc));
        const size_t len = pl.n - 5;
        if (request) {
            if (enc == 4 || enc == 1) {   // concatenated SHA-1 hashes of the acceptable CA public keys (RFC 7296 3.7)
                const size_t count = len / 20;
                Tree a = tree.add(pl, 5, len, "Certification Authority: " + std::to_string(count) + " SHA-1 hash(es)" + (len % 20 ? " [length is not a multiple of 20]" : ""));
                for (size_t i = 0; i < count && i < 16; ++i) a.add(pl, 5 + i * 20, 20, "SHA-1 hash of CA public key: " + bytesHex(pl, 5 + i * 20, 20));
            } else {
                tree.add(pl, 5, len, "Certification Authority (" + std::to_string(len) + " bytes)");
            }
        } else if ((enc == 12 || enc == 13) && len > 20) {
            tree.add(pl, 5, 20, "Certificate hash (SHA-1): " + bytesHex(pl, 5, 20));
            tree.add(pl, 25, len - 20, "URL" + (printable(pl, 25, len - 20) ? ": " + text(pl, 25, len - 20) : " (" + std::to_string(len - 20) + " bytes)"));
        } else {
            tree.add(pl, 5, len, "Certificate Data (" + std::to_string(len) + " bytes)");
        }
    }

    void v2Auth(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Authentication payload truncated]"); return; }
        const uint8_t method = pl.u8(4);
        tree.add(pl, 4, 1, "Auth Method: " + withNumber(authMethodV2(method), method));
        tree.add(pl, 8, pl.n - 8, "Authentication Data (" + std::to_string(pl.n - 8) + " bytes)");
    }

    void notifyData(const View &pl, size_t at, uint16_t type, const Tree &tree) {
        const size_t len = pl.n > at ? pl.n - at : 0;
        if (len == 0) return;
        std::string label;
        switch (type) {
            case 16388: case 16389: label = len == 20 ? "SHA-1 hash of SPIs, address and port: " + bytesHex(pl, at, len) : std::string(); break;
            case 16390: case 16401: label = "Cookie: " + bytesHex(pl, at, len, 64); break;
            case 17: if (len == 2) label = "Accepted Diffie-Hellman Group: " + withNumber(dhGroupName(pl.u16(at)), pl.u16(at)); break;
            case 16385: if (len == 4) label = "Window size: " + std::to_string(pl.u32(at)); break;
            case 16403: if (len == 4) label = "Lifetime: " + std::to_string(pl.u32(at)) + " seconds"; break;
            case 16431: {   // RFC 7427: 2 byte hash algorithm identifiers
                for (size_t i = 0; i + 2 <= len; i += 2) {
                    const unsigned id = pl.u16(at + i);
                    static const char *names[] = {"", "SHA1", "SHA2-256", "SHA2-384", "SHA2-512", "Identity"};
                    label += (i ? ", " : "Hash algorithms: ") + (id >= 1 && id <= 5 ? std::string(names[id]) : std::to_string(id)) + " (" + std::to_string(id) + ")";
                }
                break;
            }
            case 16397: case 16398: label = "Address: " + ipText(pl, at, len); break;
            default: break;
        }
        tree.add(pl, at, len, label.empty() ? "Notification Data (" + std::to_string(len) + " bytes)" : label);
    }

    void v2Notify(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Notify payload truncated]"); return; }
        const uint8_t protocol = pl.u8(4), spiSize = pl.u8(5);
        const uint16_t type = pl.u16(6);
        tree.add(pl, 4, 1, "Protocol ID: " + (protocol ? withNumber(protocolIdName(protocol), protocol) : std::string("none (0)")));
        tree.add(pl, 5, 1, "SPI Size: " + std::to_string(spiSize));
        tree.add(pl, 6, 2, "Notify Message Type: " + withNumber(ikeV2NotifyName(type), type) + (type < 16384 ? " [error]" : " [status]"));
        size_t at = 8;
        if (spiSize) {
            if (!pl.has(at, spiSize)) { tree.add(pl, at, pl.n - at, "[SPI extends beyond the payload]"); return; }
            tree.add(pl, at, spiSize, "SPI: " + bytesHex(pl, at, spiSize));
            at += spiSize;
        }
        notifyData(pl, at, type, tree);
    }

    std::string v1ProtocolName(uint8_t id) { return id == 1 ? "ISAKMP" : protocolIdName(id); }

    void deleteBody(const View &pl, const Tree &tree, bool v1) {
        size_t at = 4;
        if (v1) { if (!pl.has(at, 4)) { tree.add(pl, at, pl.n - at, "[Delete payload truncated]"); return; } tree.add(pl, at, 4, "Domain of Interpretation: " + std::to_string(pl.u32(at))); at += 4; }
        if (!pl.has(at, 4)) { tree.add(pl, at, pl.n - at, "[Delete payload truncated]"); return; }
        const uint8_t protocol = pl.u8(at), spiSize = pl.u8(at + 1);
        const uint16_t count = pl.u16(at + 2);
        tree.add(pl, at, 1, "Protocol ID: " + withNumber(v1 ? v1ProtocolName(protocol) : protocolIdName(protocol), protocol));
        tree.add(pl, at + 1, 1, "SPI Size: " + std::to_string(spiSize));
        tree.add(pl, at + 2, 2, "Number of SPIs: " + std::to_string(count));
        at += 4;
        for (unsigned i = 0; i < count && i < 64 && spiSize && pl.has(at, spiSize); ++i, at += spiSize) {
            tree.add(pl, at, spiSize, "SPI: " + bytesHex(pl, at, spiSize));
        }
    }

    void vendorBody(const View &pl, const Tree &tree) {
        const size_t len = pl.n - 4;
        const std::string known = vendorName(pl, 4, len);
        if (!known.empty()) tree.add(pl, 4, len, "Vendor ID: " + known + " (" + bytesHex(pl, 4, len, 64) + ")");
        else if (printable(pl, 4, len)) tree.add(pl, 4, len, "Vendor ID: \"" + text(pl, 4, len) + "\"");
        else tree.add(pl, 4, len, "Vendor ID: " + bytesHex(pl, 4, len, 64));
    }

    void v2Ts(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Traffic Selector payload truncated]"); return; }
        const uint8_t count = pl.u8(4);
        tree.add(pl, 4, 1, "Number of Traffic Selectors: " + std::to_string(count));
        size_t at = 8;
        for (unsigned i = 0; i < count && i < 64 && pl.has(at, 8); ++i) {
            const uint8_t type = pl.u8(at), proto = pl.u8(at + 1);
            const uint16_t length = pl.u16(at + 2);
            if (length < 8 || !pl.has(at, length)) { tree.add(pl, at, pl.n - at, "[Traffic Selector length " + std::to_string(length) + " is invalid]"); return; }
            const size_t addrLen = (length - 8) / 2;
            const std::string start = ipText(pl, at + 8, addrLen), end = ipText(pl, at + 8 + addrLen, addrLen);
            const char *typeName = type == 7 ? "TS_IPV4_ADDR_RANGE" : type == 8 ? "TS_IPV6_ADDR_RANGE" : type == 9 ? "TS_FC_ADDR_RANGE" : "TS type";
            Tree t = tree.add(pl, at, length, "Traffic Selector " + std::to_string(i + 1) + ": " + (start.empty() ? std::string(typeName) : start + " - " + end) +
                                               ", " + ipProtocolText(proto) + ", ports " + std::to_string(pl.u16(at + 4)) + "-" + std::to_string(pl.u16(at + 6)));
            t.add(pl, at, 1, "TS Type: " + withNumber(typeName, type));
            t.add(pl, at + 1, 1, "IP Protocol ID: " + ipProtocolText(proto));
            t.add(pl, at + 2, 2, "Selector Length: " + std::to_string(length));
            t.add(pl, at + 4, 2, "Start Port: " + std::to_string(pl.u16(at + 4)));
            t.add(pl, at + 6, 2, "End Port: " + std::to_string(pl.u16(at + 6)));
            if (!start.empty()) {
                t.add(pl, at + 8, addrLen, "Starting Address: " + start);
                t.add(pl, at + 8 + addrLen, addrLen, "Ending Address: " + end);
            }
            at += length;
        }
    }

    void v2Config(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Configuration payload truncated]"); return; }
        const uint8_t type = pl.u8(4);
        tree.add(pl, 4, 1, "CFG Type: " + withNumber(configTypeName(type), type));
        size_t at = 8;
        for (int i = 0; i < 64 && pl.has(at, 4); ++i) {
            const unsigned attr = pl.u16(at) & 0x7fff;
            const uint16_t length = pl.u16(at + 2);
            if (!pl.has(at, 4 + static_cast<size_t>(length))) { tree.add(pl, at, pl.n - at, "[Attribute length " + std::to_string(length) + " beyond the payload]"); return; }
            const std::string value = (attr == 1 || attr == 2 || attr == 3 || attr == 4 || attr == 6 || attr == 8 || attr == 10 || attr == 12) ? ipText(pl, at + 4, length) : std::string();
            tree.add(pl, at, 4 + length, "Attribute: " + configAttributeName(attr) + (value.empty() ? " (" + std::to_string(length) + " bytes)" : " = " + value));
            at += 4 + length;
        }
    }

    void v2Eap(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[EAP payload truncated]"); return; }
        const uint8_t code = pl.u8(4);
        tree.add(pl, 4, 1, "EAP Code: " + withNumber(eapCodeName(code), code));
        tree.add(pl, 5, 1, "EAP Identifier: " + std::to_string(pl.u8(5)));
        tree.add(pl, 6, 2, "EAP Length: " + std::to_string(pl.u16(6)));
        if ((code == 1 || code == 2) && pl.has(8, 1)) tree.add(pl, 8, 1, "EAP Type: " + std::to_string(pl.u8(8)));
    }

    // ---- IKEv1 payload bodies -----------------------------------------------------------------------------------------------------
    void v1Attributes(const View &t, size_t at, bool isakmp, const Tree &parent) {   // RFC 2408 3.3: TV (AF = 1) or TLV
        size_t i = at;
        int guard = 0;
        while (t.has(i, 4) && guard++ < 32) {
            const uint16_t word = t.u16(i);
            const bool tv = word & 0x8000;
            const unsigned type = word & 0x7fff;
            const unsigned value = t.u16(i + 2);
            if (tv) {
                parent.add(t, i, 4, v1AttributeName(isakmp, type) + ": " + v1AttributeValue(isakmp, type, value));
                i += 4;
            } else {
                if (!t.has(i, 4 + static_cast<size_t>(value))) { parent.add(t, i, t.n - i, "[Attribute extends beyond the transform]"); return; }
                std::string shown = std::to_string(value) + " bytes";
                if (value <= 4) { unsigned v = 0; for (size_t k = 0; k < value; ++k) v = (v << 8) | t.u8(i + 4 + k); shown = v1AttributeValue(isakmp, type, v); }
                parent.add(t, i, 4 + value, v1AttributeName(isakmp, type) + ": " + shown);
                i += 4 + value;
            }
        }
    }

    // The SA payload holds Proposal and Transform payloads as a chain of its own (RFC 2408 3.4 - 3.6)
    void v1Sa(const View &pl, const Tree &tree) {
        if (!pl.has(4, 8)) { tree.add(pl, 4, pl.n - 4, "[Security Association payload truncated]"); return; }
        const uint32_t doi = pl.u32(4), situation = pl.u32(8);
        tree.add(pl, 4, 4, "Domain of Interpretation: " + std::string(doi == 1 ? "IPSEC (1)" : std::to_string(doi)));
        tree.add(pl, 8, 4, "Situation: " + hexString(situation, 8) + (situation & 1 ? " (SIT_IDENTITY_ONLY)" : "") + (situation & 2 ? " (SIT_SECRECY)" : "") + (situation & 4 ? " (SIT_INTEGRITY)" : ""));
        size_t at = 12;
        int proposals = 0;
        while (pl.has(at, 8) && proposals++ < 64) {
            const uint8_t next = pl.u8(at);
            const uint16_t length = pl.u16(at + 2);
            if (length < 8 || !pl.has(at, length)) { tree.add(pl, at, pl.n - at, "[Proposal length " + std::to_string(length) + " is invalid]"); return; }
            const View prop = pl.sub(at, length);
            const uint8_t number = prop.u8(4), protocol = prop.u8(5), spiSize = prop.u8(6), transforms = prop.u8(7);
            const bool isakmp = protocol == 1;
            Tree p = tree.add(pl, at, length, "Proposal " + std::to_string(number) + ": " + (isakmp ? std::string("ISAKMP") : protocolIdName(protocol)) + ", " + std::to_string(transforms) + " transform(s)");
            p.add(prop, 0, 1, "Next Payload: " + std::to_string(next) + (next == 0 ? " (last proposal)" : " (more proposals)"));
            p.add(prop, 2, 2, "Payload Length: " + std::to_string(length));
            p.add(prop, 4, 1, "Proposal Number: " + std::to_string(number));
            p.add(prop, 5, 1, "Protocol ID: " + withNumber(isakmp ? std::string("PROTO_ISAKMP") : protocol == 2 ? "PROTO_IPSEC_AH" : protocol == 3 ? "PROTO_IPSEC_ESP" : protocol == 4 ? "PROTO_IPCOMP" : "Protocol " + std::to_string(protocol), protocol));
            p.add(prop, 6, 1, "SPI Size: " + std::to_string(spiSize));
            p.add(prop, 7, 1, "Number of Transforms: " + std::to_string(transforms));
            size_t pos = 8;
            if (spiSize) {
                if (!prop.has(pos, spiSize)) { p.add(prop, pos, prop.n - pos, "[SPI extends beyond the proposal]"); at += length; if (next == 0) break; continue; }
                p.add(prop, pos, spiSize, "SPI: " + bytesHex(prop, pos, spiSize));
                pos += spiSize;
            }
            int shown = 0;
            while (prop.has(pos, 8) && shown++ < 64) {
                const uint8_t tnext = prop.u8(pos);
                const uint16_t tlen = prop.u16(pos + 2);
                if (tlen < 8 || !prop.has(pos, tlen)) { p.add(prop, pos, prop.n - pos, "[Transform length " + std::to_string(tlen) + " is invalid]"); break; }
                const View tr = prop.sub(pos, tlen);
                const uint8_t tnum = tr.u8(4), tid = tr.u8(5);
                Tree t = p.add(prop, pos, tlen, "Transform " + std::to_string(tnum) + ": " + v1TransformIdName(protocol, tid));
                t.add(tr, 0, 1, "Next Payload: " + std::to_string(tnext) + (tnext == 0 ? " (last transform)" : " (more transforms)"));
                t.add(tr, 2, 2, "Payload Length: " + std::to_string(tlen));
                t.add(tr, 4, 1, "Transform Number: " + std::to_string(tnum));
                t.add(tr, 5, 1, "Transform ID: " + withNumber(v1TransformIdName(protocol, tid), tid));
                v1Attributes(tr, 8, isakmp, t);
                pos += tlen;
                if (tnext == 0) break;
            }
            at += length;
            if (next == 0) break;
        }
    }

    void v1Id(const View &pl, const Tree &tree) {
        if (!pl.has(4, 4)) { tree.add(pl, 4, pl.n - 4, "[Identification payload truncated]"); return; }
        const uint8_t type = pl.u8(4), protocol = pl.u8(5);
        const uint16_t port = pl.u16(6);
        const size_t len = pl.n - 8;
        tree.add(pl, 4, 1, "ID Type: " + withNumber(idTypeV1(type), type));
        tree.add(pl, 5, 1, "Protocol ID: " + ipProtocolText(protocol));
        tree.add(pl, 6, 2, "Port: " + std::to_string(port));
        std::string value;
        switch (type) {
            case 1: case 5: value = ipText(pl, 8, len); break;
            case 4: case 6: {   // address and mask
                const size_t half = len / 2;
                if (len == 8 || len == 32) value = ipText(pl, 8, half) + " / " + ipText(pl, 8 + half, half);
                break;
            }
            case 7: case 8: {
                const size_t half = len / 2;
                if (len == 8 || len == 32) value = ipText(pl, 8, half) + " - " + ipText(pl, 8 + half, half);
                break;
            }
            case 2: case 3: value = printable(pl, 8, len) ? text(pl, 8, len) : std::string(); break;
            case 11: value = bytesHex(pl, 8, len); break;
            default: break;
        }
        tree.add(pl, 8, len, "Identification Data" + (value.empty() ? " (" + std::to_string(len) + " bytes)" : ": " + value));
    }

    void v1Cert(const View &pl, const Tree &tree, bool request) {
        if (!pl.has(4, 1)) { tree.add(pl, 4, pl.n - 4, "[Certificate payload truncated]"); return; }
        const uint8_t enc = pl.u8(4);
        tree.add(pl, 4, 1, std::string(request ? "Certificate Type: " : "Certificate Encoding: ") + withNumber(certEncodingV1(enc), enc));
        tree.add(pl, 5, pl.n - 5, std::string(request ? "Certificate Authority" : "Certificate Data") + " (" + std::to_string(pl.n - 5) + " bytes)");
    }

    void v1Notification(const View &pl, const Tree &tree) {
        if (!pl.has(4, 8)) { tree.add(pl, 4, pl.n - 4, "[Notification payload truncated]"); return; }
        const uint8_t protocol = pl.u8(8), spiSize = pl.u8(9);
        const uint16_t type = pl.u16(10);
        tree.add(pl, 4, 4, "Domain of Interpretation: " + std::to_string(pl.u32(4)));
        tree.add(pl, 8, 1, "Protocol ID: " + withNumber(v1ProtocolName(protocol), protocol));
        tree.add(pl, 9, 1, "SPI Size: " + std::to_string(spiSize));
        tree.add(pl, 10, 2, "Notify Message Type: " + withNumber(notifyNameV1(type), type) + (type < 16384 ? " [error]" : " [status]"));
        size_t at = 12;
        if (spiSize) {
            if (!pl.has(at, spiSize)) { tree.add(pl, at, pl.n - at, "[SPI extends beyond the payload]"); return; }
            tree.add(pl, at, spiSize, "SPI: " + bytesHex(pl, at, spiSize));
            at += spiSize;
        }
        if (pl.n > at) tree.add(pl, at, pl.n - at, "Notification Data (" + std::to_string(pl.n - at) + " bytes)");
    }

    // ---- the chain ----------------------------------------------------------------------------------------------------------------
    void v2Body(uint8_t type, const View &pl, const Tree &tree) {
        switch (type) {
            case 33: v2Sa(pl, tree); break;
            case 34: v2Ke(pl, tree); break;
            case 35: case 36: v2Id(pl, tree); break;
            case 37: v2Cert(pl, tree, false); break;
            case 38: v2Cert(pl, tree, true); break;
            case 39: v2Auth(pl, tree); break;
            case 40: tree.add(pl, 4, pl.n - 4, "Nonce Data (" + std::to_string(pl.n - 4) + " bytes)"); break;
            case 41: v2Notify(pl, tree); break;
            case 42: deleteBody(pl, tree, false); break;
            case 43: vendorBody(pl, tree); break;
            case 44: case 45: v2Ts(pl, tree); break;
            case 46: tree.add(pl, 4, pl.n - 4, "Encrypted Data (" + std::to_string(pl.n - 4) + " bytes: IV, cipher text, padding and ICV; not interpreted)"); break;
            case 47: v2Config(pl, tree); break;
            case 48: v2Eap(pl, tree); break;
            case 53:
                if (pl.has(4, 4)) {
                    tree.add(pl, 4, 2, "Fragment Number: " + std::to_string(pl.u16(4)));
                    tree.add(pl, 6, 2, "Total Fragments: " + std::to_string(pl.u16(6)));
                    tree.add(pl, 8, pl.n - 8, "Encrypted Data (" + std::to_string(pl.n - 8) + " bytes: IV, cipher text, padding and ICV; not interpreted)");
                } else {
                    tree.add(pl, 4, pl.n - 4, "[Encrypted Fragment payload truncated]");
                }
                break;
            default: if (pl.n > 4) tree.add(pl, 4, pl.n - 4, "Payload data (" + std::to_string(pl.n - 4) + " bytes)"); break;
        }
    }

    void v1Body(uint8_t type, const View &pl, const Tree &tree) {
        switch (type) {
            case 1: v1Sa(pl, tree); break;
            case 4: tree.add(pl, 4, pl.n - 4, "Key Exchange Data (" + std::to_string(pl.n - 4) + " bytes)"); break;
            case 5: v1Id(pl, tree); break;
            case 6: v1Cert(pl, tree, false); break;
            case 7: v1Cert(pl, tree, true); break;
            case 8: tree.add(pl, 4, pl.n - 4, "Hash Data (" + std::to_string(pl.n - 4) + " bytes): " + bytesHex(pl, 4, pl.n - 4, 32)); break;
            case 9: tree.add(pl, 4, pl.n - 4, "Signature Data (" + std::to_string(pl.n - 4) + " bytes)"); break;
            case 10: tree.add(pl, 4, pl.n - 4, "Nonce Data (" + std::to_string(pl.n - 4) + " bytes)"); break;
            case 11: v1Notification(pl, tree); break;
            case 12: deleteBody(pl, tree, true); break;
            case 13: vendorBody(pl, tree); break;
            case 20: tree.add(pl, 4, pl.n - 4, "NAT-D Hash (" + std::to_string(pl.n - 4) + " bytes): " + bytesHex(pl, 4, pl.n - 4, 32)); break;
            case 21: tree.add(pl, 4, pl.n - 4, "NAT-OA: " + (ipText(pl, 8, pl.n > 8 ? pl.n - 8 : 0).empty() ? std::to_string(pl.n - 4) + " bytes" : ipText(pl, 8, pl.n - 8))); break;
            default: if (pl.n > 4) tree.add(pl, 4, pl.n - 4, "Payload data (" + std::to_string(pl.n - 4) + " bytes)"); break;
        }
    }
} // namespace

dissect::IkePayloadReport dissect::dissectIkePayloads(const uint8_t *body, size_t size, size_t bodyOffset, uint8_t version, uint8_t firstPayload,
                                                      uint8_t flags, Field *parent) {
    IkePayloadReport report;
    const View all{body, size, bodyOffset};
    const Tree root{parent};

    // IKEv1 with the encryption flag: everything after the header is cipher text (RFC 2408 3.1)
    if (version == 1 && (flags & 0x01)) {
        report.encrypted = true;
        if (size) root.add(all, 0, size, "Encrypted Payloads (" + std::to_string(size) + " bytes; not interpreted)");
        return report;
    }

    size_t at = 0;
    uint8_t current = firstPayload;
    while (current != 0 && at + 4 <= size) {
        const uint16_t plen = all.u16(at + 2);
        const size_t room = size - at;
        const bool tooLong = plen > room;
        const View pl = all.sub(at, std::min<size_t>(plen, room));
        const bool v2 = version == 2;
        const bool encrypted = v2 && (current == 46 || current == 53);
        const uint8_t next = all.u8(at);

        // facts for the summary and the list (identical in both passes)
        if (v2 ? current == 41 : current == 11) {
            if (!report.notify && plen >= 8 && !tooLong) {
                const uint16_t type = v2 ? pl.u16(6) : pl.u16(10);
                if (v2 || plen >= 12) { report.notify = true; report.notifyType = type; }
            }
        }
        if (encrypted) {
            report.encrypted = true;
            if (current == 53 && pl.has(4, 4)) { report.fragment = true; report.fragmentNumber = pl.u16(4); report.fragmentTotal = pl.u16(6); }
        }

        if (root) {
            Tree node = root.add(all, at, pl.n, "Payload: " + ikePayloadTypeName(version, current) + " (" + std::to_string(plen) + " bytes" + (tooLong ? ", beyond the packet" : "") + ")");
            const bool hasBody = !tooLong && plen >= 4;
            if (encrypted) node.add(all, at, 1, "Next Payload: " + std::to_string(next) + " (" + ikePayloadTypeName(version, next) + ")" + (current == 53 && next == 0 ? " [not the first fragment: no inner payload type]" : " [first inner payload, encrypted]"));
            else node.add(all, at, 1, "Next Payload: " + std::to_string(next) + " (" + ikePayloadTypeName(version, next) + ")");
            if (v2) node.add(all, at + 1, 1, std::string("Critical: ") + ((all.u8(at + 1) & 0x80) ? "Yes" : "No"));
            node.add(all, at + 2, 2, "Payload Length: " + std::to_string(plen));
            if (hasBody) {
                if (v2) v2Body(current, pl, node);
                else v1Body(current, pl, node);
            }
        }

        if (plen < 4) { report.malformed = "IKE payload length below the payload header"; break; }
        if (tooLong) { report.malformed = "IKE payload extends beyond the packet"; break; }
        if (encrypted) break;   // the Next Payload of SK / SKF names the first payload INSIDE the cipher text, not a following one
        at += plen;
        current = next;
    }
    return report;
}

#include "x509.h"

#include <cstdio>
#include <cstdlib>

namespace dissect {
    namespace {
        struct Tlv {
            unsigned char tag = 0;
            const unsigned char *value = nullptr;
            size_t length = 0;
            size_t total = 0;                // header + value
        };

        // Reads one TLV at p[0..n); false if it is malformed or does not fit.
        bool readTlv(const unsigned char *p, size_t n, Tlv &t) {
            if (n < 2) return false;
            t.tag = p[0];
            if ((t.tag & 0x1f) == 0x1f) return false;                  // multi-byte tags do not occur in certificates
            size_t hdr = 2, len = p[1];
            if (len & 0x80) {
                const size_t count = len & 0x7f;
                if (count == 0 || count > 3 || n < 2 + count) return false;
                len = 0;
                for (size_t i = 0; i < count; ++i) len = (len << 8) | p[2 + i];
                hdr = 2 + count;
            }
            if (n - hdr < len) return false;
            t.value = p + hdr;
            t.length = len;
            t.total = hdr + len;
            return true;
        }

        // Sequence of TLVs: calls f(tlv) for each; false if the contents are malformed.
        template<typename F>
        bool eachChild(const Tlv &parent, F &&f) {
            size_t i = 0;
            while (i < parent.length) {
                Tlv c;
                if (!readTlv(parent.value + i, parent.length - i, c)) return false;
                f(c);
                i += c.total;
            }
            return true;
        }

        const char *attributeName(const unsigned char *oid, size_t n) {
            if (n != 3 || oid[0] != 0x55 || oid[1] != 0x04) return nullptr;
            switch (oid[2]) {
                case 0x03: return "CN";
                case 0x06: return "C";
                case 0x07: return "L";
                case 0x08: return "ST";
                case 0x0a: return "O";
                case 0x0b: return "OU";
                default: return nullptr;
            }
        }

        std::string printable(const Tlv &t) {
            std::string s;
            for (size_t i = 0; i < t.length; ++i) {
                const unsigned char c = t.value[i];
                s += (c >= 32 && c < 127) ? static_cast<char>(c) : '?';
            }
            return s;
        }

        // Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value }
        std::string describeName(const Tlv &name, std::string *commonName) {
            std::string out;
            eachChild(name, [&](const Tlv &set) {
                eachChild(set, [&](const Tlv &attr) {
                    Tlv oid, value;
                    if (!readTlv(attr.value, attr.length, oid) || oid.tag != 0x06) return;
                    if (!readTlv(attr.value + oid.total, attr.length - oid.total, value)) return;
                    const char *label = attributeName(oid.value, oid.length);
                    if (!label) return;
                    const std::string text = printable(value);
                    if (!out.empty()) out += ", ";
                    out += std::string(label) + "=" + text;
                    if (commonName && std::string(label) == "CN") *commonName = text;
                });
            });
            return out;
        }

        // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ
        std::string describeTime(const Tlv &t) {
            const std::string s = printable(t);
            size_t at = 0;
            std::string year;
            if (t.tag == 0x17 && s.size() >= 12) {
                const int yy = std::atoi(s.substr(0, 2).c_str());
                year = std::to_string(yy < 50 ? 2000 + yy : 1900 + yy);
                at = 2;
            } else if (t.tag == 0x18 && s.size() >= 14) {
                year = s.substr(0, 4);
                at = 4;
            } else {
                return s;
            }
            return year + "-" + s.substr(at, 2) + "-" + s.substr(at + 2, 2) + " " + s.substr(at + 4, 2) + ":" + s.substr(at + 6, 2) + ":" +
                   s.substr(at + 8, 2) + " UTC";
        }
    } // namespace

    CertificateSummary parseCertificate(const unsigned char *der, size_t size) {
        CertificateSummary c;
        Tlv cert, tbs;
        if (!readTlv(der, size, cert) || cert.tag != 0x30) return c;
        if (!readTlv(cert.value, cert.length, tbs) || tbs.tag != 0x30) return c;

        size_t i = 0;
        Tlv f;
        auto next = [&](Tlv &out) {
            if (i >= tbs.length || !readTlv(tbs.value + i, tbs.length - i, out)) return false;
            i += out.total;
            return true;
        };
        if (!next(f)) return c;
        if (f.tag == 0xa0 && !next(f)) return c;                        // [0] version
        if (f.tag != 0x02) return c;                                    // serial number
        for (size_t k = 0; k < f.length && k < 20; ++k) {
            char b[4];
            std::snprintf(b, sizeof b, "%02x", f.value[k]);
            c.serial += b;
        }
        if (!next(f) || f.tag != 0x30) return c;                        // signature algorithm
        if (!next(f) || f.tag != 0x30) return c;                        // issuer
        c.issuer = describeName(f, nullptr);
        Tlv validity;
        if (!next(validity) || validity.tag != 0x30) return c;
        {
            Tlv a, b;
            if (readTlv(validity.value, validity.length, a) && readTlv(validity.value + a.total, validity.length - a.total, b)) {
                c.notBefore = describeTime(a);
                c.notAfter = describeTime(b);
            }
        }
        if (!next(f) || f.tag != 0x30) return c;                        // subject
        c.subject = describeName(f, &c.commonName);
        c.ok = true;
        if (!next(f)) return c;                                         // subjectPublicKeyInfo
        while (next(f)) {                                               // [3] extensions
            if (f.tag != 0xa3) continue;
            Tlv list;
            if (!readTlv(f.value, f.length, list) || list.tag != 0x30) break;
            eachChild(list, [&](const Tlv &ext) {
                Tlv oid;
                if (!readTlv(ext.value, ext.length, oid) || oid.tag != 0x06) return;
                static const unsigned char san[] = {0x55, 0x1d, 0x11};
                if (oid.length != 3 || std::string(reinterpret_cast<const char *>(oid.value), 3) != std::string(reinterpret_cast<const char *>(san), 3)) return;
                size_t at = oid.total;
                Tlv v;
                if (!readTlv(ext.value + at, ext.length - at, v)) return;
                if (v.tag == 0x01) {                                    // critical flag
                    at += v.total;
                    if (!readTlv(ext.value + at, ext.length - at, v)) return;
                }
                Tlv names;
                if (v.tag != 0x04 || !readTlv(v.value, v.length, names) || names.tag != 0x30) return;
                eachChild(names, [&](const Tlv &n) {
                    if (n.tag == 0x82 && c.dnsNames.size() < 64) c.dnsNames.push_back(printable(n));   // dNSName
                });
            });
            break;
        }
        return c;
    }
} // namespace dissect

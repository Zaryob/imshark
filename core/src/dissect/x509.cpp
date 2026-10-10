#include "x509.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "asn1.h"

namespace dissect {
    namespace {
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

        // Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value }
        std::string describeName(const BerTlv &name, std::string *commonName) {
            std::string out;
            eachChild(name, [&](const BerTlv &set) {
                eachChild(set, [&](const BerTlv &attr) {
                    BerTlv oid, value;
                    if (!readBerTlv(attr.value, attr.length, oid) || oid.rawTag != 0x06) return;
                    if (!readBerTlv(attr.value + oid.total, attr.length - oid.total, value)) return;
                    const char *label = attributeName(oid.value, oid.length);
                    if (!label) return;
                    const std::string text = value.asPrintable();
                    if (!out.empty()) out += ", ";
                    out += std::string(label) + "=" + text;
                    if (commonName && std::string(label) == "CN") *commonName = text;
                });
            });
            return out;
        }

        // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ
        std::string describeTime(const BerTlv &t) {
            std::string s = t.asPrintable();
            size_t at = 0;
            std::string year;
            if (t.rawTag == 0x17 && s.size() >= 12) {
                const int yy = static_cast<int>(std::strtol(s.substr(0, 2).c_str(), nullptr, 10));
                year = std::to_string(yy < 50 ? 2000 + yy : 1900 + yy);
                at = 2;
            } else if (t.rawTag == 0x18 && s.size() >= 14) {
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
        BerTlv cert, tbs;
        if (!readBerTlv(der, size, cert) || cert.rawTag != 0x30) return c;
        if (!readBerTlv(cert.value, cert.length, tbs) || tbs.rawTag != 0x30) return c;

        size_t i = 0;
        BerTlv f;
        auto next = [&](BerTlv &out) {
            if (i >= tbs.length || !readBerTlv(tbs.value + i, tbs.length - i, out)) return false;
            i += out.total;
            return true;
        };
        if (!next(f)) return c;
        if (f.rawTag == 0xa0 && !next(f)) return c; // [0] version
        if (f.rawTag != 0x02) return c;             // serial number
        for (size_t k = 0; k < f.length && k < 20; ++k) {
            char b[4];
            std::snprintf(b, sizeof b, "%02x", f.value[k]);
            c.serial += b;
        }
        if (!next(f) || f.rawTag != 0x30) return c; // signature algorithm
        if (!next(f) || f.rawTag != 0x30) return c; // issuer
        c.issuer = describeName(f, nullptr);
        BerTlv validity;
        if (!next(validity) || validity.rawTag != 0x30) return c;
        {
            BerTlv a, b;
            if (readBerTlv(validity.value, validity.length, a) && readBerTlv(validity.value + a.total, validity.length - a.total, b)) {
                c.notBefore = describeTime(a);
                c.notAfter = describeTime(b);
            }
        }
        if (!next(f) || f.rawTag != 0x30) return c; // subject
        c.subject = describeName(f, &c.commonName);
        c.ok = true;
        if (!next(f)) return c;                     // subjectPublicKeyInfo
        while (next(f)) {                           // [3] extensions
            if (f.rawTag != 0xa3) continue;
            BerTlv list;
            if (!readBerTlv(f.value, f.length, list) || list.rawTag != 0x30) break;
            eachChild(list, [&](const BerTlv &ext) {
                BerTlv oid;
                if (!readBerTlv(ext.value, ext.length, oid) || oid.rawTag != 0x06) return;
                static const unsigned char san[] = {0x55, 0x1d, 0x11};
                if (oid.length != 3 || std::memcmp(oid.value, san, 3) != 0) return;
                size_t at = oid.total;
                BerTlv v;
                if (!readBerTlv(ext.value + at, ext.length - at, v)) return;
                if (v.rawTag == 0x01) { // critical flag
                    at += v.total;
                    if (!readBerTlv(ext.value + at, ext.length - at, v)) return;
                }
                BerTlv names;
                if (v.rawTag != 0x04 || !readBerTlv(v.value, v.length, names) || names.rawTag != 0x30) return;
                eachChild(names, [&](const BerTlv &n) {
                    if (n.rawTag == 0x82 && c.dnsNames.size() < 64) c.dnsNames.push_back(n.asPrintable()); // dNSName
                });
            });
            break;
        }
        return c;
    }
} // namespace dissect

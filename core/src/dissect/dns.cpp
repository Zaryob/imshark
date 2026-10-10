// DNS (RFC 1035 and friends): header, flags, questions and all resource record sections with the
// common record types decoded. Also used for mDNS and for DNS over TCP.
#include "protocols.h"

#include "util.h"

#include <cstdio>
#include <string>
#include <vector>

#include <network/l7_application/dns_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    const char *typeName(uint16_t t) {
        switch (t) {
            case 1: return "A";
            case 2: return "NS";
            case 5: return "CNAME";
            case 6: return "SOA";
            case 12: return "PTR";
            case 15: return "MX";
            case 16: return "TXT";
            case 28: return "AAAA";
            case 33: return "SRV";
            case 41: return "OPT";
            case 13: return "HINFO";
            case 39: return "DNAME";
            case 43: return "DS";
            case 44: return "SSHFP";
            case 46: return "RRSIG";
            case 47: return "NSEC";
            case 48: return "DNSKEY";
            case 50: return "NSEC3";
            case 51: return "NSEC3PARAM";
            case 52: return "TLSA";
            case 64: return "SVCB";
            case 65: return "HTTPS";
            case 255: return "ANY";
            case 257: return "CAA";
            default: return nullptr;
        }
    }

    std::string typeText(uint16_t t) {
        const char *n = typeName(t);
        return n ? n : "TYPE" + std::to_string(t);
    }

    std::string classText(uint16_t c) {
        switch (c & 0x7FFF) {  // the top bit is mDNS "cache flush" / "unicast response"
            case 1: return "IN";
            case 3: return "CH";
            case 4: return "HS";
            case 254: return "NONE";
            case 255: return "ANY";
            default: return "CLASS" + std::to_string(c & 0x7FFF);
        }
    }

    std::string opcodeText(unsigned op) {
        switch (op) {
            case 0: return "Standard query";
            case 1: return "Inverse query";
            case 2: return "Server status request";
            case 4: return "Notification";
            case 5: return "Update";
            default: return "Opcode " + std::to_string(op);
        }
    }

    std::string rcodeText(unsigned rc) {
        switch (rc) {
            case 0: return "No error";
            case 1: return "Format error";
            case 2: return "Server failure";
            case 3: return "No such name";
            case 4: return "Not implemented";
            case 5: return "Refused";
            default: return "Rcode " + std::to_string(rc);
        }
    }

    // Reads a (possibly compressed) name at `off`; `off` advances past it as it appears at that position.
    // Returns false on truncation, bad labels or compression loops.
    bool readName(const char *msg, size_t len, size_t &off, std::string &out) {
        out.clear();
        size_t pos = off, resume = 0;
        bool jumped = false;
        int hops = 0;
        while (true) {
            if (pos >= len) return false;
            const uint8_t l = static_cast<uint8_t>(msg[pos]);
            if (l == 0) { ++pos; break; }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= len || ++hops > 16) return false;
                const size_t target = ((l & 0x3F) << 8) | static_cast<uint8_t>(msg[pos + 1]);
                if (!jumped) resume = pos + 2;
                jumped = true;
                pos = target;
                continue;
            }
            if ((l & 0xC0) != 0 || pos + 1 + l > len) return false;
            if (!out.empty()) out += '.';
            out.append(msg + pos + 1, l);
            pos += 1 + l;
            if (out.size() > 255) return false;
        }
        off = jumped ? resume : pos;
        if (out.empty()) out = "<Root>";
        return true;
    }

    struct Record {
        std::string name;
        uint16_t type = 0, cls = 0;
        uint32_t ttl = 0;
        size_t start = 0, dataOffset = 0, dataLength = 0, end = 0;
        std::string rdata;      // decoded record data for the tree ("addr 1.2.3.4" style pieces are in `treeText`)
        std::string infoText;   // what the Info column shows after the type
        std::string treeText;   // short description for the record's tree line
        std::vector<std::string> details;   // further lines under the record data
        unsigned extendedRcode = 0;         // OPT: upper 8 bits of the response code
        bool ok = false;
    };

    std::string quoteTxt(const char *p, size_t n) {
        std::string s = "\"";
        for (size_t i = 0; i < n; ++i) s += (static_cast<unsigned char>(p[i]) >= 32 && static_cast<unsigned char>(p[i]) < 127) ? p[i] : '.';
        return s + "\"";
    }


    std::string hexBytes(const char *p, size_t n, size_t max = 32) {
        static const char *digits = "0123456789abcdef";
        std::string out;
        for (size_t i = 0; i < std::min(n, max); ++i) {
            out += digits[static_cast<uint8_t>(p[i]) >> 4];
            out += digits[static_cast<uint8_t>(p[i]) & 15];
        }
        if (n > max) out += "...";
        return out;
    }

    std::string algorithmText(unsigned a) {
        switch (a) {
            case 1: return "RSAMD5";
            case 3: return "DSA";
            case 5: return "RSASHA1";
            case 6: return "DSA-NSEC3-SHA1";
            case 7: return "RSASHA1-NSEC3-SHA1";
            case 8: return "RSASHA256";
            case 10: return "RSASHA512";
            case 13: return "ECDSAP256SHA256";
            case 14: return "ECDSAP384SHA384";
            case 15: return "ED25519";
            case 16: return "ED448";
            default: return "algorithm " + std::to_string(a);
        }
    }

    std::string digestText(unsigned d) {
        switch (d) {
            case 1: return "SHA-1";
            case 2: return "SHA-256";
            case 3: return "GOST R 34.11-94";
            case 4: return "SHA-384";
            default: return "digest type " + std::to_string(d);
        }
    }

    // seconds since the epoch -> "2026-01-02 03:04:05 UTC" (proleptic Gregorian, no leap seconds)
    std::string utcText(uint32_t t) {
        const int64_t days = t / 86400;
        const unsigned sod = t % 86400;
        int64_t z = days + 719468;
        const int64_t era = z / 146097;
        const unsigned doe = static_cast<unsigned>(z - era * 146097);
        const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        const int64_t y = static_cast<int64_t>(yoe) + era * 400;
        const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        const unsigned mp = (5 * doy + 2) / 153;
        const unsigned d = doy - (153 * mp + 2) / 5 + 1;
        const unsigned m = mp < 10 ? mp + 3 : mp - 9;
        char buf[40];
        const long long year = static_cast<long long>(y) + (m <= 2 ? 1 : 0);
        std::snprintf(buf, sizeof buf, "%04lld-%02u-%02u %02u:%02u:%02u UTC", year, m, d, sod / 3600, sod / 60 % 60, sod % 60);
        return buf;
    }

    // NSEC / NSEC3 type bitmap: windows of {block, length, bits}
    std::string typeBitmap(const char *p, size_t n) {
        std::string out;
        size_t i = 0;
        int shown = 0;
        while (n - i >= 2) {
            const unsigned block = static_cast<uint8_t>(p[i]), len = static_cast<uint8_t>(p[i + 1]);
            if (len == 0 || len > 32 || n - i - 2 < len) break;
            for (unsigned b = 0; b < len * 8u; ++b) {
                if (static_cast<uint8_t>(p[i + 2 + b / 8]) & (0x80 >> (b % 8))) {
                    if (shown++ >= 48) return out + " ...";
                    out += (out.empty() ? "" : " ") + typeText(static_cast<uint16_t>(block * 256 + b));
                }
            }
            i += 2 + len;
        }
        return out;
    }

    std::string joinList(const std::vector<std::string> &items) {
        std::string out;
        for (size_t i = 0; i < items.size(); ++i) out += (i ? "," : "") + items[i];
        return out;
    }

    // SVCB / HTTPS SvcParams
    void decodeSvcParams(const char *d, size_t n, Record &r, std::string &summary) {
        static const char *names[] = {"mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint"};
        size_t i = 0;
        while (n - i >= 4) {
            const unsigned key = be16(d + i), len = be16(d + i + 2);
            if (n - i - 4 < len) break;
            const char *v = d + i + 4;
            const std::string keyName = key < 7 ? names[key] : "key" + std::to_string(key);
            std::string text;
            if (key == 1) {                                      // alpn: length-prefixed ids
                std::vector<std::string> ids;
                for (size_t k = 0; k < len;) {
                    const size_t l = static_cast<uint8_t>(v[k]);
                    if (k + 1 + l > len) break;
                    ids.emplace_back(v + k + 1, l);
                    k += 1 + l;
                }
                text = joinList(ids);
            } else if (key == 3 && len == 2) {
                text = std::to_string(be16(v));
            } else if (key == 4 && len % 4 == 0) {
                std::vector<std::string> a;
                for (size_t k = 0; k < len; k += 4) a.push_back(ip4(v + k));
                text = joinList(a);
            } else if (key == 6 && len % 16 == 0) {
                std::vector<std::string> a;
                for (size_t k = 0; k < len; k += 16) a.push_back(network::formatIPv6(v + k));
                text = joinList(a);
            } else if (key == 0) {
                std::vector<std::string> ks;
                for (size_t k = 0; k + 1 < len; k += 2) ks.push_back(be16(v + k) < 7 ? names[be16(v + k)] : "key" + std::to_string(be16(v + k)));
                text = joinList(ks);
            } else if (len > 0) {
                text = std::to_string(len) + " bytes";
            }
            r.details.push_back("SvcParam: " + keyName + (text.empty() ? "" : "=" + text));
            summary += " " + keyName + (text.empty() ? "" : "=" + text);
            i += 4 + len;
        }
    }

    void decodeOpt(const char *d, size_t n, Record &r) {
        size_t i = 0;
        while (n - i >= 4) {
            const unsigned code = be16(d + i), len = be16(d + i + 2);
            if (n - i - 4 < len) break;
            const char *v = d + i + 4;
            std::string text;
            switch (code) {
                case 3: text = "NSID: " + hexBytes(v, len); break;
                case 8: text = "Client subnet (family " + std::to_string(len >= 2 ? be16(v) : 0) + ", source prefix " + std::to_string(len >= 3 ? static_cast<uint8_t>(v[2]) : 0) + ")"; break;
                case 9: text = "EDNS expire"; break;
                case 10: text = "Cookie: " + hexBytes(v, len); break;
                case 11: text = "TCP keepalive"; break;
                case 12: text = "Padding: " + std::to_string(len) + " bytes"; break;
                case 15: text = "Extended DNS error " + std::to_string(len >= 2 ? be16(v) : 0) + (len > 2 ? ": " + std::string(v + 2, len - 2) : ""); break;
                default: text = "Option " + std::to_string(code) + ": " + std::to_string(len) + " bytes";
            }
            r.details.push_back(text);
            i += 4 + len;
        }
    }

    // decodes the type specific data of a record
    void decodeRdata(const char *msg, Record &r) {
        const char *d = msg + r.dataOffset;
        const size_t n = r.dataLength;
        size_t off = r.dataOffset;
        std::string name, name2;
        switch (r.type) {
            case 1:
                if (n == 4) { r.infoText = r.treeText = ip4(d); r.rdata = "Address: " + r.infoText; }
                break;
            case 28:
                if (n == 16) { r.infoText = r.treeText = network::formatIPv6(d); r.rdata = "AAAA Address: " + r.infoText; }
                break;
            case 2: case 5: case 12:
                if (readName(msg, r.dataOffset + n, off, name)) {
                    r.infoText = r.treeText = name;
                    r.rdata = std::string(r.type == 2 ? "Name Server: " : r.type == 5 ? "CNAME: " : "Domain Name: ") + name;
                }
                break;
            case 15:
                if (n >= 3) {
                    const unsigned pref = be16(d);
                    off += 2;
                    if (readName(msg, r.dataOffset + n, off, name)) {
                        r.infoText = std::to_string(pref) + " " + name;
                        r.treeText = "preference " + std::to_string(pref) + ", mx " + name;
                        r.rdata = "Preference: " + std::to_string(pref) + ", Mail Exchange: " + name;
                    }
                }
                break;
            case 16: { // one or more length-prefixed strings
                size_t i = 0;
                std::string all;
                while (i < n) {
                    const size_t sl = static_cast<uint8_t>(d[i]);
                    if (i + 1 + sl > n) break;
                    if (!all.empty()) all += ' ';
                    all += quoteTxt(d + i + 1, sl);
                    i += 1 + sl;
                }
                r.infoText = r.treeText = all;
                r.rdata = "TXT: " + all;
                break;
            }
            case 6:
                if (readName(msg, r.dataOffset + n, off, name) && readName(msg, r.dataOffset + n, off, name2) && off + 20 <= r.dataOffset + n) {
                    r.infoText = name + " " + name2;
                    r.treeText = "mname " + name + ", rname " + name2;
                    r.rdata = "Primary name server: " + name + ", Responsible authority: " + name2 + ", Serial: " + std::to_string(be32(msg + off)) +
                              ", Minimum TTL: " + std::to_string(be32(msg + off + 16));
                    r.details = {"Serial Number: " + std::to_string(be32(msg + off)), "Refresh Interval: " + std::to_string(be32(msg + off + 4)) + " seconds",
                                 "Retry Interval: " + std::to_string(be32(msg + off + 8)) + " seconds", "Expire limit: " + std::to_string(be32(msg + off + 12)) + " seconds",
                                 "Minimum TTL: " + std::to_string(be32(msg + off + 16)) + " seconds"};
                }
                break;
            case 33:
                if (n >= 7) {
                    off += 6;
                    if (readName(msg, r.dataOffset + n, off, name)) {
                        r.infoText = std::to_string(be16(d)) + " " + std::to_string(be16(d + 2)) + " " + std::to_string(be16(d + 4)) + " " + name;
                        r.treeText = "priority " + std::to_string(be16(d)) + ", weight " + std::to_string(be16(d + 2)) + ", port " + std::to_string(be16(d + 4)) + ", target " + name;
                        r.rdata = "Priority: " + std::to_string(be16(d)) + ", Weight: " + std::to_string(be16(d + 2)) + ", Port: " + std::to_string(be16(d + 4)) + ", Target: " + name;
                    }
                }
                break;
            case 41: { // EDNS0 pseudo record: the class field carries the UDP payload size, the TTL the extended flags
                r.infoText = "<Root>";
                r.treeText = "UDP payload size " + std::to_string(r.cls);
                r.extendedRcode = r.ttl >> 24;
                r.details.push_back("Higher bits in extended RCODE: " + hexString(r.ttl >> 24, 2));
                r.details.push_back("EDNS0 version: " + std::to_string((r.ttl >> 16) & 0xff));
                r.details.push_back(std::string("DO bit: ") + ((r.ttl & 0x8000) ? "Accepts DNSSEC security RRs" : "Cannot handle DNSSEC security RRs"));
                decodeOpt(d, n, r);
                break;
            }
            case 39:
                if (readName(msg, r.dataOffset + n, off, name)) { r.infoText = r.treeText = name; r.rdata = "Delegation name: " + name; }
                break;
            case 13: // HINFO: two character strings
                if (n >= 2 && 1u + static_cast<uint8_t>(d[0]) < n) {
                    const size_t cl = static_cast<uint8_t>(d[0]);
                    const size_t ol = static_cast<uint8_t>(d[1 + cl]);
                    if (2 + cl + ol <= n) {
                        r.infoText = r.treeText = quoteTxt(d + 1, cl) + " " + quoteTxt(d + 2 + cl, ol);
                        r.rdata = "CPU: " + quoteTxt(d + 1, cl) + ", OS: " + quoteTxt(d + 2 + cl, ol);
                    }
                }
                break;
            case 43: // DS
                if (n >= 4) {
                    r.infoText = std::to_string(be16(d)) + " " + algorithmText(static_cast<uint8_t>(d[2])) + " " + digestText(static_cast<uint8_t>(d[3]));
                    r.treeText = "key tag " + std::to_string(be16(d)) + ", " + algorithmText(static_cast<uint8_t>(d[2]));
                    r.rdata = "Delegation Signer";
                    r.details = {"Key Tag: " + std::to_string(be16(d)), "Algorithm: " + algorithmText(static_cast<uint8_t>(d[2])) + " (" + std::to_string(static_cast<uint8_t>(d[2])) + ")",
                                 "Digest Type: " + digestText(static_cast<uint8_t>(d[3])) + " (" + std::to_string(static_cast<uint8_t>(d[3])) + ")", "Digest: " + hexBytes(d + 4, n - 4)};
                }
                break;
            case 48: // DNSKEY
                if (n >= 4) {
                    const unsigned flags = be16(d);
                    const char *role = (flags & 1) ? "Key Signing Key" : (flags & 0x100) ? "Zone Signing Key" : "Key";
                    r.infoText = std::string(role) + " " + algorithmText(static_cast<uint8_t>(d[3]));
                    r.treeText = std::string(role) + ", " + algorithmText(static_cast<uint8_t>(d[3]));
                    r.rdata = "DNS Key";
                    r.details = {"Flags: " + hexString(flags, 4) + (flags & 0x100 ? " (zone key)" : "") + (flags & 1 ? " (secure entry point)" : ""),
                                 "Protocol: " + std::to_string(static_cast<uint8_t>(d[2])), "Algorithm: " + algorithmText(static_cast<uint8_t>(d[3])) + " (" + std::to_string(static_cast<uint8_t>(d[3])) + ")",
                                 "Public Key: " + std::to_string(n - 4) + " bytes " + hexBytes(d + 4, n - 4, 16)};
                }
                break;
            case 46: // RRSIG
                if (n >= 18) {
                    size_t at = r.dataOffset + 18;
                    if (readName(msg, r.dataOffset + n, at, name2)) {
                        r.infoText = typeText(be16(d)) + " " + algorithmText(static_cast<uint8_t>(d[2])) + " " + name2;
                        r.treeText = "covers " + typeText(be16(d)) + ", signer " + name2;
                        r.rdata = "RRSIG";
                        r.details = {"Type Covered: " + typeText(be16(d)), "Algorithm: " + algorithmText(static_cast<uint8_t>(d[2])) + " (" + std::to_string(static_cast<uint8_t>(d[2])) + ")",
                                     "Labels: " + std::to_string(static_cast<uint8_t>(d[3])), "Original TTL: " + std::to_string(be32(d + 4)),
                                     "Signature Expiration: " + utcText(be32(d + 8)), "Signature Inception: " + utcText(be32(d + 12)),
                                     "Key Tag: " + std::to_string(be16(d + 16)), "Signer's name: " + name2,
                                     "Signature: " + std::to_string(r.dataOffset + n - at) + " bytes"};
                    }
                }
                break;
            case 47: // NSEC: next domain name + type bitmap
                if (readName(msg, r.dataOffset + n, off, name) && off <= r.dataOffset + n) {
                    const std::string types = typeBitmap(msg + off, r.dataOffset + n - off);
                    r.infoText = name + " " + types;
                    r.treeText = "next " + name;
                    r.rdata = "Next domain name: " + name;
                    r.details = {"Record types in bitmap: " + types};
                }
                break;
            case 50: // NSEC3
                if (n >= 5) {
                    const size_t saltLen = static_cast<uint8_t>(d[4]);
                    if (5 + saltLen + 1 <= n) {
                        const size_t hashLen = static_cast<uint8_t>(d[5 + saltLen]);
                        if (6 + saltLen + hashLen <= n) {
                            r.infoText = "iterations " + std::to_string(be16(d + 2)) + " " + typeBitmap(d + 6 + saltLen + hashLen, n - 6 - saltLen - hashLen);
                            r.treeText = "hash algorithm " + std::to_string(static_cast<uint8_t>(d[0])) + ", iterations " + std::to_string(be16(d + 2));
                            r.rdata = "NSEC3";
                            r.details = {"Hash algorithm: " + std::to_string(static_cast<uint8_t>(d[0])), std::string("Opt-out flag: ") + ((d[1] & 1) ? "set" : "not set"),
                                         "Iterations: " + std::to_string(be16(d + 2)), "Salt: " + (saltLen ? hexBytes(d + 5, saltLen) : std::string("-")),
                                         "Next hashed owner: " + hexBytes(d + 6 + saltLen, hashLen),
                                         "Record types in bitmap: " + typeBitmap(d + 6 + saltLen + hashLen, n - 6 - saltLen - hashLen)};
                        }
                    }
                }
                break;
            case 51: // NSEC3PARAM
                if (n >= 5 && 5u + static_cast<uint8_t>(d[4]) <= n) {
                    const size_t saltLen = static_cast<uint8_t>(d[4]);
                    r.infoText = "iterations " + std::to_string(be16(d + 2));
                    r.treeText = "hash algorithm " + std::to_string(static_cast<uint8_t>(d[0])) + ", iterations " + std::to_string(be16(d + 2));
                    r.rdata = "NSEC3PARAM";
                    r.details = {"Hash algorithm: " + std::to_string(static_cast<uint8_t>(d[0])), "Iterations: " + std::to_string(be16(d + 2)), "Salt: " + (saltLen ? hexBytes(d + 5, saltLen) : std::string("-"))};
                }
                break;
            case 52: // TLSA
                if (n >= 3) {
                    r.infoText = std::to_string(static_cast<uint8_t>(d[0])) + " " + std::to_string(static_cast<uint8_t>(d[1])) + " " + std::to_string(static_cast<uint8_t>(d[2]));
                    r.treeText = "usage " + std::to_string(static_cast<uint8_t>(d[0])) + ", selector " + std::to_string(static_cast<uint8_t>(d[1])) + ", matching type " + std::to_string(static_cast<uint8_t>(d[2]));
                    r.rdata = "TLSA";
                    r.details = {"Certificate Usage: " + std::to_string(static_cast<uint8_t>(d[0])), "Selector: " + std::to_string(static_cast<uint8_t>(d[1])),
                                 "Matching Type: " + std::to_string(static_cast<uint8_t>(d[2])), "Certificate Association Data: " + hexBytes(d + 3, n - 3)};
                }
                break;
            case 257: // CAA
                if (n >= 2 && 2u + static_cast<uint8_t>(d[1]) <= n) {
                    const size_t tl = static_cast<uint8_t>(d[1]);
                    const std::string tag(d + 2, tl), value(d + 2 + tl, n - 2 - tl);
                    r.infoText = std::to_string(static_cast<uint8_t>(d[0])) + " " + tag + " " + quoteTxt(value.data(), value.size());
                    r.treeText = tag + " " + quoteTxt(value.data(), value.size());
                    r.rdata = "CAA";
                    r.details = {"Flags: " + std::to_string(static_cast<uint8_t>(d[0])), "Tag: " + tag, "Value: " + value};
                }
                break;
            case 64: case 65: // SVCB / HTTPS
                if (n >= 3) {
                    size_t at = off + 2;
                    if (readName(msg, r.dataOffset + n, at, name) && at <= r.dataOffset + n) {
                        const unsigned priority = be16(d);
                        std::string params;
                        decodeSvcParams(msg + at, r.dataOffset + n - at, r, params);
                        r.infoText = std::to_string(priority) + " " + name + params;
                        r.treeText = (priority == 0 ? "alias " : "priority " + std::to_string(priority) + ", ") + std::string(priority == 0 ? "" : "target ") + name;
                        r.rdata = std::string(priority == 0 ? "AliasMode" : "ServiceMode") + ": priority " + std::to_string(priority) + ", target " + name;
                    }
                }
                break;
            default:
                r.treeText = std::to_string(n) + " bytes of data";
        }
        if (r.rdata.empty()) {   // not decoded (unknown type or damaged data): shown as raw bytes, never silently dropped
            r.rdata = "Data (" + std::to_string(n) + " bytes)" + (n ? ": " + hexBytes(d, n, 24) : std::string());
            if (r.treeText.empty()) r.treeText = std::to_string(n) + " bytes of data";
        }
    }

    bool parseRecord(const char *msg, size_t len, size_t &off, Record &r) {
        r.start = off;
        if (!readName(msg, len, off, r.name)) return false;
        if (len < off || len - off < 10) return false;
        r.type = be16(msg + off);
        r.cls = be16(msg + off + 2);
        r.ttl = be32(msg + off + 4);
        r.dataLength = be16(msg + off + 8);
        off += 10;
        if (len - off < r.dataLength) return false;
        r.dataOffset = off;
        off += r.dataLength;
        r.end = off;
        decodeRdata(msg, r);
        r.ok = true;
        return true;
    }

    void addFlagBits(Field &flags, uint16_t f, size_t o) {
        auto bit = [&](uint16_t mask, const char *pattern, const char *on, const char *off) {
            flags.add(std::string(pattern) + (f & mask ? on : off), o, 2);
        };
        bit(0x8000, "1... .... .... .... = Response: ", "Message is a response", "Message is a query");
        flags.add(".... " + std::string("Opcode: ") + opcodeText((f >> 11) & 0xF) + " (" + std::to_string((f >> 11) & 0xF) + ")", o, 2);
        bit(0x0400, ".... .1.. .... .... = Authoritative: ", "Server is an authority for domain", "Server is not an authority for domain");
        bit(0x0200, ".... ..1. .... .... = Truncated: ", "Message is truncated", "Message is not truncated");
        bit(0x0100, ".... ...1 .... .... = Recursion desired: ", "Do query recursively", "Do not query recursively");
        bit(0x0080, ".... .... 1... .... = Recursion available: ", "Server can do recursive queries", "Server cannot do recursive queries");
        bit(0x0020, ".... .... ..1. .... = Answer authenticated: ", "Answer/authority portion was authenticated by the server", "Answer/authority portion was not authenticated by the server");
        bit(0x0010, ".... .... ...1 .... = Non-authenticated data: ", "Acceptable", "Unacceptable");
        flags.add("Reply code: " + rcodeText(f & 0xF) + " (" + std::to_string(f & 0xF) + ")", o, 2);
    }

    void dissectMessage(Context &ctx, const char *msg, size_t len, const char *protocolName) {
        auto &pack = ctx.pack;
        pack.protocol = protocolName;

        network::DNSHeader hdr;
        if (!readStruct(msg, len, 0, hdr)) {
            ctx.markMalformed("DNS message too short");
            return;
        }
        const uint16_t id = network::ntoh16(hdr.transaction_id);
        const uint16_t flags = network::ntoh16(hdr.flags);
        const uint16_t counts[4] = {network::ntoh16(hdr.questions), network::ntoh16(hdr.answer_rrs),
                                    network::ntoh16(hdr.authority_rrs), network::ntoh16(hdr.additional_rrs)};
        const bool response = flags & 0x8000;
        const unsigned rcode = flags & 0xF;
        pack.app_flags = flags;
        pack.app_code = static_cast<uint16_t>(rcode);

        const size_t o = ctx.offsetOf(msg);
        Field *layer = nullptr;
        if (ctx.wantFields()) {
            layer = &ctx.addLayer(std::string("Domain Name System (") + (response ? "response" : "query") + ")", o, len);
            layer->add("Transaction ID: " + hexString(id, 4), o, 2);
            Field &f = layer->add("Flags: " + hexString(flags, 4) + " " + opcodeText((flags >> 11) & 0xF) + (response ? " response" : "") +
                                      ", " + rcodeText(rcode), o + 2, 2);
            addFlagBits(f, flags, o + 2);
            layer->add("Questions: " + std::to_string(counts[0]), o + 4, 2);
            layer->add("Answer RRs: " + std::to_string(counts[1]), o + 6, 2);
            layer->add("Authority RRs: " + std::to_string(counts[2]), o + 8, 2);
            layer->add("Additional RRs: " + std::to_string(counts[3]), o + 10, 2);
        }

        std::string info = opcodeText((flags >> 11) & 0xF) + (response ? " response 0x" : " 0x");
        { std::ostringstream h; h << std::hex << id; info += h.str(); }
        if (response && rcode != 0) info += " " + rcodeText(rcode);
        unsigned extendedRcode = 0;

        size_t off = sizeof(network::DNSHeader);
        bool ok = true;
        static const char *sectionNames[4] = {"Queries", "Answers", "Authoritative nameservers", "Additional records"};
        int infoRecords = 0;

        for (int section = 0; section < 4 && ok; ++section) {
            Field *sec = nullptr;
            if (layer && counts[section] > 0) {
                layer->add(sectionNames[section], o + off, 0);
                sec = &layer->children.back();
            }
            const size_t sectionStart = off;
            for (unsigned i = 0; i < counts[section] && ok; ++i) {
                if (section == 0) { // a question: name, type, class
                    const size_t start = off;
                    std::string name;
                    if (!readName(msg, len, off, name) || len < off || len - off < 4) { ok = false; break; }
                    const uint16_t t = be16(msg + off), c = be16(msg + off + 2);
                    off += 4;
                    if (i == 0) {
                        pack.app_text = name;
                        pack.app_type = t;
                    }
                    info += " " + typeText(t) + " " + name;
                    if (sec) {
                        Field &q = sec->add(name + ": type " + typeText(t) + ", class " + classText(c), o + start, off - start);
                        q.add("Name: " + name, o + start, off - start - 4);
                        q.add("Type: " + typeText(t) + " (" + std::to_string(t) + ")", o + off - 4, 2);
                        q.add("Class: " + classText(c) + " (" + hexString(c, 4) + ")", o + off - 2, 2);
                    }
                } else {
                    Record r;
                    if (!parseRecord(msg, len, off, r)) { ok = false; break; }
                    if (r.type == 41) extendedRcode = r.extendedRcode;
                    if (r.type != 41 && infoRecords < 8) { // OPT pseudo records are not interesting in the Info column
                        info += " " + typeText(r.type) + (r.infoText.empty() ? "" : " " + r.infoText);
                        ++infoRecords;
                    } else if (r.type != 41 && infoRecords == 8) {
                        info += " ...";
                        ++infoRecords;
                    }
                    if (sec) {
                        Field &rr = sec->add(r.name + ": type " + typeText(r.type) + ", class " + classText(r.cls) +
                                                 (r.treeText.empty() ? "" : ", " + r.treeText),
                                             o + r.start, r.end - r.start);
                        rr.add("Name: " + r.name, o + r.start, r.dataOffset - 10 - r.start);
                        rr.add("Type: " + typeText(r.type) + " (" + std::to_string(r.type) + ")", o + r.dataOffset - 10, 2);
                        rr.add("Class: " + classText(r.cls) + " (" + hexString(r.cls, 4) + ")", o + r.dataOffset - 8, 2);
                        rr.add("Time to live: " + std::to_string(r.ttl), o + r.dataOffset - 6, 4);
                        rr.add("Data length: " + std::to_string(r.dataLength), o + r.dataOffset - 2, 2);
                        Field &data = rr.add(r.rdata, o + r.dataOffset, r.dataLength);
                        for (const auto &line: r.details) data.add(line, o + r.dataOffset, r.dataLength);
                    }
                }
            }
            if (sec) { sec->offset = static_cast<uint32_t>(o + sectionStart); sec->length = static_cast<uint32_t>(off - sectionStart); }
        }
        if (response && extendedRcode != 0) info += " (extended rcode " + std::to_string((extendedRcode << 4) | rcode) + ")";
        if (!ok) info += " [Malformed Packet: truncated DNS record]";
        pack.info = info;
    }
} // namespace

void dissect::dissectDns(Context &ctx, const char *data, size_t length) { dissectMessage(ctx, data, length, "DNS"); }

void dissect::dissectMdns(Context &ctx, const char *data, size_t length) { dissectMessage(ctx, data, length, "MDNS"); }

dissect::StreamFrame dissect::frameDnsTcp(const char *data, size_t length) {
    // a 2-byte length followed by a message that is at least a DNS header long and no longer than the length says
    if (length < 2) return {StreamFrame::Kind::NeedMore, 0};
    const size_t declared = be16(data);
    if (declared < sizeof(network::DNSHeader)) return {StreamFrame::Kind::Reject, 0};
    if (length < declared + 2) return {StreamFrame::Kind::NeedMore, 0};
    return {StreamFrame::Kind::Complete, declared + 2};
}

namespace {
    // A message is DNS only if all of it parses: header sanity, then every question and record, ending exactly at its end.
    bool looksLikeDns(const char *msg, size_t len) {
        network::DNSHeader hdr;
        if (!readStruct(msg, len, 0, hdr) || len > 4096) return false;
        const uint16_t flags = network::ntoh16(hdr.flags);
        const unsigned opcode = (flags >> 11) & 0xF, rcode = flags & 0xF;
        if (opcode > 5 || opcode == 3 || (flags & 0x0040) || rcode > 10) return false;   // reserved opcode / Z bit / unknown rcode
        const unsigned counts[4] = {network::ntoh16(hdr.questions), network::ntoh16(hdr.answer_rrs), network::ntoh16(hdr.authority_rrs), network::ntoh16(hdr.additional_rrs)};
        if (counts[0] > 8 || counts[1] > 64 || counts[2] > 64 || counts[3] > 64) return false;
        if (opcode == 0 && counts[0] == 0) return false;
        if (counts[0] + counts[1] + counts[2] + counts[3] == 0) return false;
        size_t off = sizeof(network::DNSHeader);
        for (int section = 0; section < 4; ++section) {
            for (unsigned i = 0; i < counts[section]; ++i) {
                std::string name;
                if (section == 0) {
                    if (!readName(msg, len, off, name) || len < off || len - off < 4) return false;
                    const unsigned cls = be16(msg + off + 2) & 0x7FFF;
                    if (cls != 1 && cls != 3 && cls != 4 && cls != 254 && cls != 255) return false;
                    off += 4;
                } else {
                    Record r;
                    if (!parseRecord(msg, len, off, r)) return false;
                }
            }
        }
        return off == len;
    }
} // namespace

bool dissect::dissectDnsHeuristic(Context &ctx, const char *data, size_t length) {
    if (!looksLikeDns(data, length)) return false;
    dissectMessage(ctx, data, length, "DNS");
    return true;
}

dissect::StreamFrame dissect::frameDnsTcpHeuristic(const char *data, size_t length) {
    const StreamFrame f = frameDnsTcp(data, length);
    if (f.kind == StreamFrame::Kind::Reject) return f;
    // the length alone is a weak signal: it must be a plausible DNS size, and the message after it must also begin like DNS
    if (be16(data) > 4096) return {StreamFrame::Kind::Reject, 0};
    if (length >= 4 && (be16(data + 2 + 0) & 0x0040)) return {StreamFrame::Kind::Reject, 0};   // flags are not available before 4 bytes
    if (length >= 2 + sizeof(network::DNSHeader)) {
        const uint16_t flags = be16(data + 2 + 2);
        const unsigned opcode = (flags >> 11) & 0xF;
        const unsigned questions = be16(data + 2 + 4);
        if (opcode > 5 || opcode == 3 || (flags & 0x0040) || (flags & 0xF) > 10 || questions == 0 || questions > 8) return {StreamFrame::Kind::Reject, 0};
        if (f.kind == StreamFrame::Kind::Complete && !looksLikeDns(data + 2, f.length - 2)) return {StreamFrame::Kind::Reject, 0};
    }
    return f;
}

void dissect::dissectDnsTcp(Context &ctx, const char *data, size_t length) {
    // DNS over TCP: every message is preceded by its length (RFC 1035 4.2.2). Whole messages come from the
    // stream reassembly; what is present gets decoded when that did not apply (a capture that starts mid-stream).
    if (length < 2) {
        ctx.pack.protocol = "DNS";
        ctx.markMalformed("DNS over TCP: missing length field");
        return;
    }
    const size_t declared = be16(data);
    const size_t available = std::min(declared, length - 2);
    dissectMessage(ctx, data + 2, available, "DNS");
    if (available < declared) ctx.pack.info += " [message continues in later segments: " + std::to_string(available) + " of " + std::to_string(declared) + " bytes]";
}

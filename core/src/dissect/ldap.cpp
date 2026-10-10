// LDAP (Lightweight Directory Access Protocol, RFC 4511) dissector using BER (asn1.h)
#include "ldap.h"

#include <string>
#include <vector>

#include "asn1.h"
#include "spnego.h"
#include "util.h"

using packet::Field;

namespace {
    using namespace dissect;

    constexpr const char *kStartTlsOid = "1.3.6.1.4.1.1466.20037";   // RFC 4511 4.14.1
    constexpr size_t kMaxMessage = 8u << 20;                          // like the other framers: not more than the stream table buffers

    std::string ldapOpName(uint32_t tag) {
        switch (tag) {
            case 0: return "BindRequest";
            case 1: return "BindResponse";
            case 2: return "UnbindRequest";
            case 3: return "SearchRequest";
            case 4: return "SearchResultEntry";
            case 5: return "SearchResultDone";
            case 6: return "ModifyRequest";
            case 7: return "ModifyResponse";
            case 8: return "AddRequest";
            case 9: return "AddResponse";
            case 10: return "DelRequest";
            case 11: return "DelResponse";
            case 12: return "ModDNRequest";
            case 13: return "ModDNResponse";
            case 14: return "CompareRequest";
            case 15: return "CompareResponse";
            case 16: return "AbandonRequest";
            case 19: return "SearchResultReference";
            case 23: return "ExtendedRequest";
            case 24: return "ExtendedResponse";
            case 25: return "IntermediateResponse";
            default: return "Op [Application " + std::to_string(tag) + "]";
        }
    }

    // RFC 4511 4.1.9 resultCode
    std::string ldapResultCodeName(int64_t code) {
        switch (code) {
            case 0: return "success";
            case 1: return "operationsError";
            case 2: return "protocolError";
            case 3: return "timeLimitExceeded";
            case 4: return "sizeLimitExceeded";
            case 5: return "compareFalse";
            case 6: return "compareTrue";
            case 7: return "authMethodNotSupported";
            case 8: return "strongerAuthRequired";
            case 10: return "referral";
            case 11: return "adminLimitExceeded";
            case 12: return "unavailableCriticalExtension";
            case 13: return "confidentialityRequired";
            case 14: return "saslBindInProgress";
            case 16: return "noSuchAttribute";
            case 17: return "undefinedAttributeType";
            case 18: return "inappropriateMatching";
            case 19: return "constraintViolation";
            case 20: return "attributeOrValueExists";
            case 21: return "invalidAttributeSyntax";
            case 32: return "noSuchObject";
            case 33: return "aliasProblem";
            case 34: return "invalidDNSyntax";
            case 36: return "aliasDereferencingProblem";
            case 48: return "inappropriateAuthentication";
            case 49: return "invalidCredentials";
            case 50: return "insufficientAccessRights";
            case 51: return "busy";
            case 52: return "unavailable";
            case 53: return "unwillingToPerform";
            case 54: return "loopDetect";
            case 64: return "namingViolation";
            case 65: return "objectClassViolation";
            case 66: return "notAllowedOnNonLeaf";
            case 67: return "notAllowedOnRDN";
            case 68: return "entryAlreadyExists";
            case 69: return "objectClassModsProhibited";
            case 71: return "affectsMultipleDSAs";
            case 80: return "other";
            default: return "code " + std::to_string(code);
        }
    }

    const char *scopeName(int64_t scope) {
        switch (scope) {
            case 0: return "baseObject";
            case 1: return "singleLevel";
            case 2: return "wholeSubtree";
            default: return "unknown";
        }
    }

    std::string text(const BerTlv &t) { return printableText(t.value, t.length); }

    size_t tlvOffset(const Context &ctx, const BerTlv &t) { return ctx.offsetOf(reinterpret_cast<const char *>(t.value)) - t.headerLength; }

    // Attributes whose values are credentials: never shown (only their length), in entries, changes, comparisons and filters.
    bool sensitiveAttribute(const std::string &name) {
        std::string l;
        for (char c: name) l += static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
        return l.find("password") != std::string::npos || l.find("pwd") != std::string::npos || l == "krb5key" ||
               l == "supplementalcredentials" || l == "userpkcs12" || l == "authpassword";
    }

    // An attribute value: printable text, or the length and the first bytes for binary data; credentials are hidden.
    std::string valueText(const std::string &attr, const BerTlv &v) {
        if (sensitiveAttribute(attr)) return "<hidden, " + std::to_string(v.length) + " bytes>";
        bool binary = false;
        for (size_t i = 0; i < v.length; ++i) if (v.value[i] < 32 || v.value[i] == 127) { binary = true; break; }
        if (!binary) return printableText(v.value, v.length);
        std::string s = "0x";
        for (size_t i = 0; i < v.length && i < 16; ++i) { char b[4]; std::snprintf(b, sizeof b, "%02x", v.value[i]); s += b; }
        return s + (v.length > 16 ? "..." : "") + " (" + std::to_string(v.length) + " bytes)";
    }

    // RFC 4515 3: a filter value escapes * ( ) \ and NUL as \hh; other control and high bytes are written the same way.
    std::string filterValue(const std::string &attr, const BerTlv &v) {
        if (sensitiveAttribute(attr)) return "<hidden>";
        std::string s;
        for (size_t i = 0; i < v.length && i < 200; ++i) {
            const unsigned char c = v.value[i];
            if (c == '*' || c == '(' || c == ')' || c == '\\' || c < 32 || c >= 127) { char b[8]; std::snprintf(b, sizeof b, "\\%02x", c); s += b; }
            else s += static_cast<char>(c);
        }
        return s;
    }

    // Names of well-known controls (RFC 4511 4.1.11) and extended operations (RFC 4511 4.12).
    const char *controlName(const std::string &oid) {
        static const std::pair<const char *, const char *> k[] = {
            {"1.2.840.113556.1.4.319", "Paged Results"}, {"1.2.840.113556.1.4.473", "Server Side Sort Request"},
            {"1.2.840.113556.1.4.474", "Server Side Sort Response"}, {"2.16.840.1.113730.3.4.2", "ManageDsaIT"},
            {"1.2.840.113556.1.4.801", "SD Flags"}, {"1.2.840.113556.1.4.417", "Show Deleted"},
            {"1.2.840.113556.1.4.529", "Extended DN"}, {"1.2.840.113556.1.4.528", "Change Notification"},
            {"1.2.840.113556.1.4.1339", "Domain Scope"}, {"1.2.840.113556.1.4.1340", "Search Options"},
            {"2.16.840.1.113730.3.4.9", "VLV Request"}, {"2.16.840.1.113730.3.4.10", "VLV Response"},
            {"2.16.840.1.113730.3.4.3", "Persistent Search"}, {"2.16.840.1.113730.3.4.7", "Entry Change Notification"},
            {"2.16.840.1.113730.3.4.18", "Proxied Authorization"}, {"1.3.6.1.4.1.42.2.27.8.5.1", "Password Policy"},
            {"1.3.6.1.4.1.4203.1.9.1.1", "Content Synchronization"}, {"1.3.6.1.1.12", "Assertion"},
            {"1.3.6.1.1.13.1", "Pre-Read"}, {"1.3.6.1.1.13.2", "Post-Read"}, {"1.2.826.0.1.3344810.2.3", "Matched Values"},
            {"1.3.6.1.4.1.1466.20037", "StartTLS"}, {"1.3.6.1.4.1.4203.1.11.1", "Password Modify"},
            {"1.3.6.1.4.1.4203.1.11.3", "Who am I?"}, {"1.3.6.1.1.8", "Cancel"},
            {"1.3.6.1.4.1.1466.20036", "Notice of Disconnection"}, {"1.3.6.1.4.1.1466.101.119.1", "Dynamic Refresh"},
        };
        for (const auto &e: k) if (oid == e.first) return e.second;
        return nullptr;
    }

    std::string describeOid(const std::string &oid) {
        const char *n = controlName(oid);
        return n ? oid + " (" + n + ")" : oid;
    }

    // Search filter (RFC 4511 4.5.1.7) in the string form of RFC 4515; `depth` bounds the nesting.
    std::string filterText(const BerTlv &f, int depth) {
        if (depth <= 0 || f.tagClass != asn1::ContextSpecific) return "(?)";
        ByteReader r(f.value, f.length);
        switch (f.tagNumber) {
            case 0: case 1: { // and, or: SET OF Filter
                std::string s = f.tagNumber == 0 ? "(&" : "(|";
                BerTlv c;
                int n = 0;
                while (r.remaining() > 0 && readBerTlv(r, c) && n++ < 32) s += filterText(c, depth - 1);
                return s + ")";
            }
            case 2: { // not: Filter
                BerTlv c;
                return readBerTlv(r, c) ? "(!" + filterText(c, depth - 1) + ")" : "(!?)";
            }
            case 3: case 5: case 6: case 8: { // equalityMatch, greaterOrEqual, lessOrEqual, approxMatch: AttributeValueAssertion
                BerTlv a, v;
                if (!readBerTlv(r, a) || !readBerTlv(r, v)) return "(?)";
                const char *op = f.tagNumber == 3 ? "=" : f.tagNumber == 5 ? ">=" : f.tagNumber == 6 ? "<=" : "~=";
                return "(" + text(a) + op + filterValue(text(a), v) + ")";
            }
            case 4: { // substrings: type, SEQUENCE OF CHOICE { initial [0], any [1], final [2] }
                BerTlv type, seq;
                if (!readBerTlv(r, type) || !readBerTlv(r, seq)) return "(?)";
                const std::string attr = text(type);
                std::string s = "(" + attr + "=";
                bool first = true;
                ByteReader sr(seq.value, seq.length);
                BerTlv part;
                int n = 0;
                while (sr.remaining() > 0 && readBerTlv(sr, part) && n++ < 32) {
                    const std::string v = filterValue(attr, part);
                    if (part.isContext(0)) s += v + "*";
                    else if (part.isContext(1)) s += (first && s.back() == '=' ? "*" : "") + v + "*";
                    else if (part.isContext(2)) s += (s.back() == '=' ? "*" : "") + v;
                    first = false;
                }
                if (first) s += "*";
                return s + ")";
            }
            case 7: return "(" + text(f) + "=*)"; // present
            case 9: { // extensibleMatch: matchingRule [1], type [2], matchValue [3], dnAttributes [4]  ->  (type:dn:rule:=value)
                BerTlv e;
                std::string rule, type, value;
                bool dn = false;
                int n = 0;
                while (r.remaining() > 0 && readBerTlv(r, e) && n++ < 8) {
                    if (e.isContext(1)) rule = text(e);
                    else if (e.isContext(2)) type = text(e);
                    else if (e.isContext(3)) value = filterValue(type, e);
                    else if (e.isContext(4)) dn = e.length > 0 && e.value[0] != 0;
                }
                return "(" + type + (dn ? ":dn" : "") + (rule.empty() ? "" : ":" + rule) + ":=" + value + ")";
            }
            default: return "(?)";
        }
    }

    // The length of an LDAPMessage: tag 0x30 and its BER length. `needMore`: the length bytes are not all there.
    struct Header {
        bool ok = false, needMore = false;
        size_t header = 0, body = 0;
    };

    Header ldapHeader(const uint8_t *p, size_t n) {
        Header h;
        if (n >= 1 && p[0] != 0x30) return h;
        if (n < 2) { h.needMore = true; return h; }
        if (p[1] < 0x80) {
            h.header = 2;
            h.body = p[1];
        } else {
            const size_t count = p[1] & 0x7f;
            if (count == 0 || count > 4) return h;   // indefinite length (X.690 8.1.3.6) is not used by LDAP (RFC 4511 5.1)
            if (n < 2 + count) { h.needMore = true; return h; }
            for (size_t i = 0; i < count; ++i) h.body = (h.body << 8) | p[2 + i];
            h.header = 2 + count;
        }
        if (h.header + h.body > kMaxMessage) return Header{};
        h.ok = true;
        return h;
    }
} // namespace

dissect::StreamFrame dissect::frameLdap(const char *data, size_t length) {
    const auto *p = reinterpret_cast<const uint8_t *>(data);
    const Header h = ldapHeader(p, length);
    if (h.needMore) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    if (!h.ok) return StreamFrame{StreamFrame::Kind::Reject, 0};
    // the first element of an LDAPMessage is the messageID INTEGER
    if (length > h.header && p[h.header] != 0x02) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (h.body == 0) return StreamFrame{StreamFrame::Kind::Reject, 0};
    const size_t total = h.header + h.body;
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

void dissect::dissectLdap(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "LDAP";
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    const Header h = ldapHeader(bytes, length);
    if (!h.ok) {
        pack.info = "LDAP";
        ctx.markMalformed("LDAP message does not start with a SEQUENCE");
        return;
    }
    const size_t total = h.header + h.body;
    const size_t avail = std::min(total, length);
    const bool cut = total > length;   // a segment of a longer message, or a cut capture

    // MessageID (INTEGER), ProtocolOp (APPLICATION tag), optional controls
    ByteReader body(bytes + h.header, avail - h.header);
    BerTlv idTlv;
    int64_t msgId = 0;
    if (!readBerTlv(body, idTlv) || !idTlv.isUniversal(asn1::tag::Integer) || !idTlv.asInt64(msgId) || msgId < 0 || msgId > 0x7fffffff) {
        pack.info = "LDAP";
        if (cut) pack.info += " [cut]";   // the rest is in the next segment
        else ctx.markMalformed("LDAP MessageID missing");
        return;
    }
    pack.app_stream = static_cast<uint32_t>(msgId);

    // the operation's header on its own: its content may be cut
    const size_t opStart = h.header + idTlv.total;
    if (avail - opStart < 2 || (bytes[opStart] & 0xc0) != 0x40 || (bytes[opStart] & 0x1f) == 0x1f) {
        pack.info = "LDAP MsgID=" + std::to_string(msgId);
        if (cut) pack.info += " [cut]";
        else ctx.markMalformed("LDAP protocolOp missing");
        return;
    }
    const uint32_t opTag = bytes[opStart] & 0x1f;
    const bool opConstructed = (bytes[opStart] & 0x20) != 0;
    pack.app_type = static_cast<uint16_t>(opTag);
    const std::string opName = ldapOpName(opTag);

    BerTlv opTlv;   // complete if the message is
    ByteReader opHeaderReader(bytes + opStart, avail - opStart);
    const bool opComplete = readBerTlv(opHeaderReader, opTlv);
    // a cut operation is read as far as its complete elements go
    size_t opHeader = 2;
    if (!opComplete && bytes[opStart + 1] >= 0x80) opHeader = 2 + (bytes[opStart + 1] & 0x7f);
    const uint8_t *opValue = opComplete ? opTlv.value : bytes + opStart + std::min(opHeader, avail - opStart);
    const size_t opLength = opComplete ? opTlv.length : avail - opStart - std::min(opHeader, avail - opStart);
    ByteReader opReader(opValue, opLength);

    const bool tree = ctx.wantFields();
    std::string detail, targetName, extendedName;
    std::vector<Field> items;   // detail-tree children of the operation
    Field scratch;              // where tree-building helpers write when only the summary is wanted
    auto addItem = [&](const std::string &label, const BerTlv &t) -> Field & {
        if (!tree) { scratch.children.clear(); return scratch; }
        items.push_back(Field{label, static_cast<uint32_t>(tlvOffset(ctx, t)), static_cast<uint32_t>(t.total), {}});
        return items.back();
    };
    bool hasResult = false;
    int64_t resultCode = 0;
    // a node of the tree under `parent` for an element of the message (nullptr when only the summary is wanted)
    auto node = [&](Field *parent, const std::string &label, const BerTlv &t) -> Field * {
        return parent ? &parent->add(label, tlvOffset(ctx, t), t.total) : nullptr;
    };

    constexpr int kMaxListed = 64;   // attributes / values / changes shown per list; the rest is counted
    // PartialAttribute / Attribute ::= SEQUENCE { type, vals SET OF value }: one node, the values below it (credentials hidden)
    auto attribute = [&](Field *parent, const BerTlv &pa, std::string *nameOut) {
        ByteReader r(pa.value, pa.length);
        BerTlv type, vals;
        if (!pa.constructed || !readBerTlv(r, type) || !readBerTlv(r, vals) || !vals.constructed) return;
        const std::string name = text(type);
        if (nameOut) *nameOut = name;
        if (!parent) return;
        std::vector<std::string> shown;
        size_t count = 0;
        ByteReader vr(vals.value, vals.length);
        BerTlv v;
        while (vr.remaining() > 0 && readBerTlv(vr, v)) {
            if (shown.size() < 32) shown.push_back(valueText(name, v));
            ++count;
        }
        Field *a;
        if (count == 1) {
            a = node(parent, name + ": " + shown[0], pa);
        } else {
            a = node(parent, name + (count == 0 ? " (no values)" : " (" + std::to_string(count) + " values)"), pa);
            ByteReader vr2(vals.value, vals.length);
            size_t n = 0;
            while (vr2.remaining() > 0 && readBerTlv(vr2, v) && n < shown.size()) a->add(shown[n++], tlvOffset(ctx, v), v.total);
            if (count > shown.size()) a->add("... " + std::to_string(count - shown.size()) + " more values");
        }
    };
    // SEQUENCE OF attribute: returns how many there are; `names` collects the first few
    auto attributeList = [&](Field *parent, const BerTlv &list, std::string *names) -> size_t {
        size_t count = 0;
        if (!list.constructed) return 0;
        ByteReader r(list.value, list.length);
        BerTlv pa;
        while (r.remaining() > 0 && readBerTlv(r, pa)) {
            std::string name;
            if (count < kMaxListed) attribute(parent, pa, &name);
            if (names && count < 8) *names += (names->empty() ? "" : ",") + name;
            ++count;
        }
        if (parent && count > kMaxListed) parent->add("... " + std::to_string(count - kMaxListed) + " more attributes");
        return count;
    };

    auto readResult = [&]() { // LDAPResult: resultCode, matchedDN, diagnosticMessage, referral [3] (RFC 4511 4.1.9)
        BerTlv code, dn, msg;
        if (!readBerTlv(opReader, code) || !code.asInt64(resultCode)) return;
        hasResult = true;
        addItem("Result Code: " + ldapResultCodeName(resultCode) + " (" + std::to_string(resultCode) + ")", code);
        detail = "result=" + ldapResultCodeName(resultCode);
        if (readBerTlv(opReader, dn) && dn.length > 0) addItem("Matched DN: " + text(dn), dn);
        if (readBerTlv(opReader, msg) && msg.length > 0) {
            addItem("Diagnostic Message: " + text(msg), msg);
            if (resultCode != 0) detail += ", \"" + printableText(msg.value, msg.length, 80) + "\"";
        }
        BerTlv ref;
        ByteReader peek = opReader;
        if (opReader.remaining() > 0 && readBerTlv(peek, ref) && ref.isContext(3)) { // referral: SEQUENCE OF URI
            opReader = peek;
            Field &r = addItem("Referral", ref);
            ByteReader rr(ref.value, ref.length);
            BerTlv uri;
            int n = 0;
            while (rr.remaining() > 0 && readBerTlv(rr, uri) && n++ < 16) {
                if (tree) r.add(text(uri), tlvOffset(ctx, uri), uri.total);
                if (n == 1) detail += ", referral=" + text(uri);
            }
        }
    };

    // SASL credentials (bind request / server credentials of a response): the mechanism and the size; a GSS-API token is decoded
    auto saslCredentials = [&](const std::string &mech, const BerTlv &creds, const std::string &label) {
        Field &c = addItem(label + " (" + std::to_string(creds.length) + " bytes)", creds);
        if (creds.length == 0) return;
        if (mech == "GSS-SPNEGO" || mech == "GSSAPI" || mech.empty()) {
            const SecurityBlob blob = decodeSecurityBlob(ctx, creds.value, creds.length, tree ? &c : nullptr);
            if (blob.ok) detail += ", " + blob.summary;
            else detail += ", " + std::to_string(creds.length) + " bytes";
        } else {
            detail += ", " + std::to_string(creds.length) + " bytes";
        }
    };

    if (opConstructed) {
        switch (opTag) {
            case 0: { // BindRequest: version INTEGER, name LDAPDN, authentication CHOICE { simple [0], sasl [3] }
                BerTlv ver, name, auth;
                if (readBerTlv(opReader, ver) && readBerTlv(opReader, name)) {
                    int64_t v = 0;
                    ver.asInt64(v);
                    addItem("Version: " + std::to_string(v), ver);
                    targetName = text(name);
                    addItem("Name: " + (targetName.empty() ? std::string("<anonymous>") : targetName), name);
                    detail = "name=\"" + (targetName.empty() ? std::string("<anonymous>") : targetName) + "\"";
                    if (readBerTlv(opReader, auth)) {
                        if (auth.isContext(0)) {
                            addItem("Authentication: simple (password: " + std::to_string(auth.length) + " bytes, not shown)", auth);
                            detail += ", simple";
                        } else if (auth.isContext(3)) { // SaslCredentials ::= SEQUENCE { mechanism, credentials OPTIONAL } (the [3] is the sequence)
                            ByteReader sr(auth.value, auth.length);
                            BerTlv mech, creds;
                            const bool haveMech = readBerTlv(sr, mech);
                            const std::string m = haveMech ? text(mech) : std::string("?");
                            Field &a = addItem("Authentication: SASL " + m, auth);
                            detail += ", SASL " + m;
                            if (tree && haveMech) a.add("Mechanism: " + m, tlvOffset(ctx, mech), mech.total);
                            if (haveMech && readBerTlv(sr, creds)) {
                                Field *holder = tree ? &a : nullptr;
                                Field &c = holder ? holder->add("Credentials (" + std::to_string(creds.length) + " bytes)", tlvOffset(ctx, creds), creds.total) : scratch;
                                if (creds.length > 0 && (m == "GSS-SPNEGO" || m == "GSSAPI")) {
                                    const SecurityBlob blob = decodeSecurityBlob(ctx, creds.value, creds.length, holder ? &c : nullptr);
                                    detail += blob.ok ? ", " + blob.summary : ", token " + std::to_string(creds.length) + " bytes";
                                } else if (creds.length > 0) {
                                    detail += ", token " + std::to_string(creds.length) + " bytes";   // other mechanisms: size only (PLAIN carries the password)
                                }
                            }
                        }
                    }
                }
                break;
            }
            case 1: case 5: case 7: case 9: case 11: case 13: case 15: { // responses: LDAPResult; a bind response may carry serverSaslCreds [7]
                readResult();
                BerTlv t;
                while (opTag == 1 && opReader.remaining() > 0 && readBerTlv(opReader, t)) {
                    if (t.isContext(7)) saslCredentials("", t, "Server SASL Credentials");
                }
                break;
            }
            case 24: { // ExtendedResponse: LDAPResult, responseName [10], responseValue [11]
                readResult();
                BerTlv t;
                while (opReader.remaining() > 0 && readBerTlv(opReader, t)) {
                    if (t.isContext(10)) {
                        extendedName = text(t);
                        addItem("Response Name: " + describeOid(extendedName), t);
                    } else if (t.isContext(11)) {
                        addItem("Response Value (" + std::to_string(t.length) + " bytes, not decoded)", t);
                    }
                }
                if (extendedName == kStartTlsOid) detail += ", StartTLS";
                else if (!extendedName.empty()) detail += ", name=" + extendedName;
                break;
            }
            case 25: { // IntermediateResponse: responseName [0], responseValue [1]
                BerTlv t;
                while (opReader.remaining() > 0 && readBerTlv(opReader, t)) {
                    if (t.isContext(0)) { extendedName = text(t); addItem("Response Name: " + describeOid(extendedName), t); detail = "name=" + extendedName; }
                    else if (t.isContext(1)) addItem("Response Value (" + std::to_string(t.length) + " bytes, not decoded)", t);
                }
                break;
            }
            case 3: { // SearchRequest: baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes
                BerTlv base, scope, deref, size, time, types, filter, attrs;
                if (readBerTlv(opReader, base)) {
                    targetName = text(base);
                    addItem("Base Object: " + targetName, base);
                    detail = "base=\"" + targetName + "\"";
                    int64_t sc = 0, sl = 0, tl = 0;
                    if (readBerTlv(opReader, scope) && scope.asInt64(sc)) {
                        addItem(std::string("Scope: ") + scopeName(sc) + " (" + std::to_string(sc) + ")", scope);
                        detail += std::string(", scope=") + scopeName(sc);
                    }
                    if (readBerTlv(opReader, deref)) addItem("Deref Aliases: " + std::to_string(deref.length ? deref.value[0] : 0), deref);
                    if (readBerTlv(opReader, size) && size.asInt64(sl)) addItem("Size Limit: " + std::to_string(sl), size);
                    if (readBerTlv(opReader, time) && time.asInt64(tl)) addItem("Time Limit: " + std::to_string(tl), time);
                    if (readBerTlv(opReader, types)) addItem(std::string("Types Only: ") + (types.length && types.value[0] ? "true" : "false"), types);
                    if (readBerTlv(opReader, filter)) {
                        const std::string f = filterText(filter, 8);
                        addItem("Filter: " + f, filter);
                        detail += ", filter=" + (f.size() > 120 ? f.substr(0, 120) + "..." : f);
                    }
                    if (readBerTlv(opReader, attrs) && attrs.constructed) { // SEQUENCE OF AttributeSelection (LDAPString)
                        std::string list;
                        size_t n = 0;
                        ByteReader ar(attrs.value, attrs.length);
                        BerTlv a;
                        while (ar.remaining() > 0 && readBerTlv(ar, a)) {
                            if (n < 16) list += (list.empty() ? "" : ", ") + text(a);
                            ++n;
                        }
                        addItem("Attributes (" + std::to_string(n) + "): " + (n == 0 ? std::string("all user attributes") : list + (n > 16 ? ", ..." : "")), attrs);
                    }
                }
                break;
            }
            case 4: { // SearchResultEntry: objectName, attributes PartialAttributeList
                BerTlv obj, attrs;
                if (readBerTlv(opReader, obj)) {
                    targetName = text(obj);
                    addItem("Object Name: " + targetName, obj);
                    detail = "entry=\"" + targetName + "\"";
                    if (readBerTlv(opReader, attrs)) {
                        Field *list = nullptr;
                        if (tree) {
                            items.push_back(Field{"Attributes", static_cast<uint32_t>(tlvOffset(ctx, attrs)), static_cast<uint32_t>(attrs.total), {}});
                            list = &items.back();
                        }
                        const size_t n = attributeList(list, attrs, nullptr);
                        if (list) list->text = "Attributes: " + std::to_string(n);
                    }
                }
                break;
            }
            case 6: { // ModifyRequest: object, changes SEQUENCE OF { operation ENUMERATED { add 0, delete 1, replace 2, increment 3 }, modification PartialAttribute }
                BerTlv dn, changes;
                if (readBerTlv(opReader, dn)) {
                    targetName = text(dn);
                    addItem("Object: " + targetName, dn);
                    detail = "entry=\"" + targetName + "\"";
                    if (readBerTlv(opReader, changes) && changes.constructed) {
                        Field *list = nullptr;
                        if (tree) {
                            items.push_back(Field{"Changes", static_cast<uint32_t>(tlvOffset(ctx, changes)), static_cast<uint32_t>(changes.total), {}});
                            list = &items.back();
                        }
                        static const char *ops[] = {"add", "delete", "replace", "increment"};
                        size_t n = 0;
                        std::string summary;
                        ByteReader cr(changes.value, changes.length);
                        BerTlv ch;
                        while (cr.remaining() > 0 && readBerTlv(cr, ch)) {
                            if (n < kMaxListed && ch.constructed) {
                                ByteReader sr(ch.value, ch.length);
                                BerTlv opn, mod;
                                int64_t o = -1;
                                if (readBerTlv(sr, opn) && opn.asInt64(o) && readBerTlv(sr, mod)) {
                                    const std::string modName = o >= 0 && o < 4 ? ops[o] : "operation " + std::to_string(o);
                                    std::string attr;
                                    attribute(nullptr, mod, &attr);
                                    if (n < 4) summary += (summary.empty() ? "" : ", ") + modName + " " + attr;
                                    if (list) {
                                        Field *c = node(list, "Change: " + modName + " " + attr, ch);
                                        attribute(c, mod, nullptr);
                                    }
                                }
                            }
                            ++n;
                        }
                        if (list) { list->text = "Changes: " + std::to_string(n); if (n > kMaxListed) list->add("... " + std::to_string(n - kMaxListed) + " more changes"); }
                        if (!summary.empty()) detail += ", " + summary + (n > 4 ? ", ..." : "");
                    }
                }
                break;
            }
            case 8: { // AddRequest: entry, attributes AttributeList
                BerTlv dn, attrs;
                if (readBerTlv(opReader, dn)) {
                    targetName = text(dn);
                    addItem("Entry: " + targetName, dn);
                    detail = "entry=\"" + targetName + "\"";
                    if (readBerTlv(opReader, attrs)) {
                        Field *list = nullptr;
                        if (tree) {
                            items.push_back(Field{"Attributes", static_cast<uint32_t>(tlvOffset(ctx, attrs)), static_cast<uint32_t>(attrs.total), {}});
                            list = &items.back();
                        }
                        std::string names;
                        const size_t n = attributeList(list, attrs, &names);
                        if (list) list->text = "Attributes: " + std::to_string(n);
                        detail += ", attrs=" + (names.empty() ? std::to_string(n) : names + (n > 8 ? ",..." : ""));
                    }
                }
                break;
            }
            case 12: { // ModifyDNRequest: entry, newrdn, deleteoldrdn BOOLEAN, newSuperior [0] OPTIONAL
                BerTlv dn, rdn, del, sup;
                if (readBerTlv(opReader, dn)) {
                    targetName = text(dn);
                    addItem("Entry: " + targetName, dn);
                    detail = "entry=\"" + targetName + "\"";
                    if (readBerTlv(opReader, rdn)) {
                        addItem("New RDN: " + text(rdn), rdn);
                        detail += ", newrdn=" + text(rdn);
                    }
                    if (readBerTlv(opReader, del)) addItem(std::string("Delete Old RDN: ") + (del.length && del.value[0] ? "true" : "false"), del);
                    if (readBerTlv(opReader, sup) && sup.isContext(0)) {
                        addItem("New Superior: " + text(sup), sup);
                        detail += ", newsuperior=" + text(sup);
                    }
                }
                break;
            }
            case 14: { // CompareRequest: entry, ava AttributeValueAssertion
                BerTlv dn, ava;
                if (readBerTlv(opReader, dn)) {
                    targetName = text(dn);
                    addItem("Entry: " + targetName, dn);
                    detail = "entry=\"" + targetName + "\"";
                    if (readBerTlv(opReader, ava) && ava.constructed) {
                        ByteReader ar(ava.value, ava.length);
                        BerTlv attr, val;
                        if (readBerTlv(ar, attr) && readBerTlv(ar, val)) {
                            const std::string a = text(attr), v = valueText(a, val);
                            Field &f = addItem("Assertion: " + a + " = " + v, ava);
                            (void) f;
                            detail += ", " + a + "=" + v;
                        }
                    }
                }
                break;
            }
            case 19: { // SearchResultReference: SEQUENCE OF LDAPURL
                int n = 0;
                BerTlv uri;
                while (opReader.remaining() > 0 && readBerTlv(opReader, uri) && n++ < 16) {
                    addItem("URI: " + text(uri), uri);
                    if (n == 1) detail = "uri=" + text(uri);
                }
                break;
            }
            case 23: { // ExtendedRequest: requestName [0], requestValue [1]
                BerTlv name, value;
                if (readBerTlv(opReader, name) && name.isContext(0)) {
                    extendedName = text(name);
                    addItem("Request Name: " + describeOid(extendedName), name);
                    detail = extendedName == kStartTlsOid ? "StartTLS" : "name=" + extendedName;
                    // the value can hold credentials (Password Modify): its size only
                    if (readBerTlv(opReader, value) && value.isContext(1)) addItem("Request Value (" + std::to_string(value.length) + " bytes, not decoded)", value);
                }
                break;
            }
            default: break;
        }
    } else if (opComplete) {
        if (opTag == 10) { // DelRequest: LDAPDN
            targetName = printableText(opValue, opLength);
            detail = "entry=\"" + targetName + "\"";
        } else if (opTag == 16 && opLength > 0 && opLength <= 4) { // AbandonRequest: MessageID
            uint32_t id = 0;
            for (size_t i = 0; i < opLength; ++i) id = (id << 8) | opValue[i];
            detail = "abandon MsgID=" + std::to_string(id);
        }
    }

    // Controls [0] after the operation (RFC 4511 4.1.11): SEQUENCE OF Control { controlType, criticality BOOLEAN DEFAULT FALSE, controlValue OCTET STRING }
    std::vector<Field> controlItems;
    BerTlv controls;
    bool haveControls = false;
    if (opComplete && opStart + opTlv.total < avail) {
        ByteReader cr(bytes + opStart + opTlv.total, avail - opStart - opTlv.total);
        haveControls = readBerTlv(cr, controls) && controls.isContext(0) && controls.constructed;
    }
    if (haveControls && tree) {
        ByteReader lr(controls.value, controls.length);
        BerTlv ctl;
        size_t n = 0;
        Field list{"Controls", static_cast<uint32_t>(tlvOffset(ctx, controls)), static_cast<uint32_t>(controls.total), {}};
        while (lr.remaining() > 0 && readBerTlv(lr, ctl)) {
            if (n++ >= 16) { list.add("... more controls"); break; }
            ByteReader sr(ctl.value, ctl.length);
            BerTlv type, next;
            if (!ctl.constructed || !readBerTlv(sr, type)) continue;
            Field &c = list.add("Control: " + describeOid(text(type)), tlvOffset(ctx, ctl), ctl.total);
            bool critical = false;
            ByteReader peek = sr;
            if (readBerTlv(peek, next) && next.isUniversal(asn1::tag::Boolean)) {
                critical = next.length && next.value[0];
                c.add(std::string("Criticality: ") + (critical ? "true" : "false"), tlvOffset(ctx, next), next.total);
                sr = peek;
            }
            if (readBerTlv(sr, next) && next.isUniversal(asn1::tag::OctetString)) {
                Field &v = c.add("Control Value (" + std::to_string(next.length) + " bytes)", tlvOffset(ctx, next), next.total);
                if (text(type) == "1.2.840.113556.1.4.319" && next.length > 0) { // paged results: SEQUENCE { size INTEGER, cookie OCTET STRING }
                    ByteReader vr(next.value, next.length);
                    BerTlv seq, size, cookie;
                    int64_t sz = 0;
                    if (readBerTlv(vr, seq) && seq.constructed) {
                        ByteReader ir(seq.value, seq.length);
                        if (readBerTlv(ir, size) && size.asInt64(sz)) v.add("Size: " + std::to_string(sz), tlvOffset(ctx, size), size.total);
                        if (readBerTlv(ir, cookie)) v.add("Cookie: " + std::to_string(cookie.length) + " bytes", tlvOffset(ctx, cookie), cookie.total);
                    }
                }
            }
        }
        controlItems.push_back(std::move(list));
    }

    if (hasResult) {
        pack.app_code = static_cast<uint16_t>(resultCode);
        pack.app_flags |= 1;
    }
    pack.app_text = targetName;
    pack.app_text2 = extendedName;
    pack.info = opName + " (MsgID=" + std::to_string(msgId) + (detail.empty() ? "" : ", " + detail) + ")";

    // StartTLS agreed (load pass only: the session tables are frozen afterwards): what follows in both directions is TLS
    if (opTag == 24 && hasResult && resultCode == 0 && extendedName == kStartTlsOid && ctx.sessions && ctx.tcpStreamSeq >= 0 && pack.tcp_relative_ack >= 0) {
        const uint32_t serverNext = static_cast<uint32_t>(ctx.tcpStreamSeq) + static_cast<uint32_t>(total);
        ctx.sessions->markTlsUpgrade(pack.source, pack.src_port, pack.destination, pack.dst_port, serverNext);
        ctx.sessions->markTlsUpgrade(pack.destination, pack.dst_port, pack.source, pack.src_port, static_cast<uint32_t>(pack.tcp_relative_ack));
        pack.info += " - TLS follows";
    }

    if (tree) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Lightweight Directory Access Protocol (" + opName + ")", o, avail);
        l.add("Message ID: " + std::to_string(msgId), o + h.header, idTlv.total);
        const size_t opLen = opComplete ? opTlv.total : avail - opStart;
        Field &opf = l.add("ProtocolOp: " + opName + " (Application " + std::to_string(opTag) + ")", o + opStart, opLen);
        for (auto &it: items) opf.children.push_back(std::move(it));
        if (!detail.empty() && items.empty()) opf.add("Details: " + detail);
        for (auto &c: controlItems) l.children.push_back(std::move(c));
    }

    // a message that continues in the next segment (cut) is not an error; one whose parts contradict each other is
    if (!cut && !opComplete) ctx.markMalformed("LDAP protocolOp longer than the message");
}

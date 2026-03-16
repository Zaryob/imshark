// LDAP (Lightweight Directory Access Protocol, RFC 4511) dissector using BER (asn1.h)
#include "ldap.h"

#include <string>
#include <vector>

#include "asn1.h"
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
                return "(" + text(a) + op + text(v) + ")";
            }
            case 4: { // substrings: type, SEQUENCE OF CHOICE { initial [0], any [1], final [2] }
                BerTlv type, seq;
                if (!readBerTlv(r, type) || !readBerTlv(r, seq)) return "(?)";
                std::string s = "(" + text(type) + "=", tail;
                bool first = true;
                ByteReader sr(seq.value, seq.length);
                BerTlv part;
                int n = 0;
                while (sr.remaining() > 0 && readBerTlv(sr, part) && n++ < 32) {
                    if (part.isContext(0)) s += text(part) + "*";
                    else if (part.isContext(1)) s += (first && s.back() == '=' ? "*" : "") + text(part) + "*";
                    else if (part.isContext(2)) s += (s.back() == '=' ? "*" : "") + text(part);
                    first = false;
                }
                if (first) s += "*";
                return s + ")";
            }
            case 7: return "(" + text(f) + "=*)"; // present
            case 9: return "(extensibleMatch)";
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
        ctx.markMalformed(cut ? "LDAP message cut before its MessageID" : "LDAP MessageID missing");
        return;
    }
    pack.app_stream = static_cast<uint32_t>(msgId);

    // the operation's header on its own: its content may be cut
    const size_t opStart = h.header + idTlv.total;
    if (avail - opStart < 2 || (bytes[opStart] & 0xc0) != 0x40 || (bytes[opStart] & 0x1f) == 0x1f) {
        pack.info = "LDAP MsgID=" + std::to_string(msgId);
        ctx.markMalformed(cut ? "LDAP message cut before its protocolOp" : "LDAP protocolOp missing");
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

    std::string detail, targetName, extendedName;
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    auto addItem = [&](const std::string &label, const BerTlv &t) {
        items.push_back({label, {ctx.offsetOf(reinterpret_cast<const char *>(t.value)) - t.headerLength, t.total}});
    };
    bool hasResult = false;
    int64_t resultCode = 0;

    auto readResult = [&]() { // LDAPResult: resultCode, matchedDN, diagnosticMessage (RFC 4511 4.1.9)
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
                            addItem("Authentication: simple (the password is not shown)", auth);
                            detail += ", simple";
                        } else if (auth.isContext(3)) {
                            ByteReader sr(auth.value, auth.length);
                            BerTlv mech;
                            const std::string m = readBerTlv(sr, mech) ? text(mech) : std::string("?");
                            addItem("Authentication: SASL " + m, auth);
                            detail += ", SASL " + m;
                        }
                    }
                }
                break;
            }
            case 1: case 5: case 7: case 9: case 11: case 13: case 15: // responses: LDAPResult
                readResult();
                break;
            case 24: { // ExtendedResponse: LDAPResult, responseName [10], responseValue [11]
                readResult();
                BerTlv t;
                while (opReader.remaining() > 0 && readBerTlv(opReader, t)) {
                    if (t.isContext(10)) {
                        extendedName = text(t);
                        addItem("Response Name: " + extendedName + (extendedName == kStartTlsOid ? " (StartTLS)" : ""), t);
                    }
                }
                if (extendedName == kStartTlsOid) detail += ", StartTLS";
                else if (!extendedName.empty()) detail += ", name=" + extendedName;
                break;
            }
            case 3: { // SearchRequest: baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes
                BerTlv base, scope, deref, size, time, types, filter;
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
                        ByteReader ar(attrs.value, attrs.length);
                        BerTlv a;
                        int n = 0;
                        while (ar.remaining() > 0 && readBerTlv(ar, a)) ++n;
                        addItem("Attributes: " + std::to_string(n), attrs);
                    }
                }
                break;
            }
            case 6: case 8: case 12: case 14: { // Modify/Add/ModDN/Compare requests: the entry is the first element
                BerTlv dn;
                if (readBerTlv(opReader, dn)) {
                    targetName = text(dn);
                    addItem("Entry: " + targetName, dn);
                    detail = "entry=\"" + targetName + "\"";
                }
                break;
            }
            case 23: { // ExtendedRequest: requestName [0], requestValue [1]
                BerTlv name;
                if (readBerTlv(opReader, name) && name.isContext(0)) {
                    extendedName = text(name);
                    addItem("Request Name: " + extendedName + (extendedName == kStartTlsOid ? " (StartTLS)" : ""), name);
                    detail = extendedName == kStartTlsOid ? "StartTLS" : "name=" + extendedName;
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

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Lightweight Directory Access Protocol (" + opName + ")", o, avail);
        l.add("Message ID: " + std::to_string(msgId), o + h.header, idTlv.total);
        const size_t opLen = opComplete ? opTlv.total : avail - opStart;
        Field &opf = l.add("ProtocolOp: " + opName + " (Application " + std::to_string(opTag) + ")", o + opStart, opLen);
        for (const auto &it: items) opf.add(it.first, it.second.first, it.second.second);
        if (!detail.empty() && items.empty()) opf.add("Details: " + detail);
    }

    // a message that continues in the next segment (cut) is not an error; one whose parts contradict each other is
    if (!cut && !opComplete) ctx.markMalformed("LDAP protocolOp longer than the message");
}

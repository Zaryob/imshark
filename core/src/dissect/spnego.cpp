// GSS-API / SPNEGO security blob decoder, see spnego.h.
//   InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE { thisMech OID, innerContextToken ANY }   (RFC 2743 3.1)
//   Kerberos 5 innerContextToken: TOK_ID (2 bytes: 01 00 AP-REQ, 02 00 AP-REP, 03 00 KRB-ERROR) + the Kerberos message   (RFC 4121 4.1)
//   NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, negTokenResp [1] NegTokenResp }   (RFC 4178 4.2)
//   NegTokenInit ::= SEQUENCE { mechTypes [0] MechTypeList, reqFlags [1] BIT STRING, mechToken [2] OCTET STRING, mechListMIC [3] OCTET STRING }
//   NegTokenResp ::= SEQUENCE { negState [0] ENUMERATED, supportedMech [1] OID, responseToken [2] OCTET STRING, mechListMIC [3] OCTET STRING }
#include "spnego.h"

#include <cstring>

#include "asn1.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr const char *kSpnego = "1.3.6.1.5.5.2";

bool isKerberosMech(const std::string &oid) {
    return oid == "1.2.840.113554.1.2.2" || oid == "1.2.840.48018.1.2.2" || oid == "1.2.840.113554.1.2.2.3";
}

// The TLV inside the EXPLICIT context tag [n] of a SEQUENCE.
bool child(const BerTlv &seq, uint32_t n, BerTlv &out) {
    if (!seq.constructed || !seq.value) return false;
    ByteReader r(seq.value, seq.length);
    BerTlv e;
    int count = 0;
    while (r.remaining() > 0 && readBerTlv(r, e) && count++ < 16) {
        if (!e.isContext(n)) continue;
        ByteReader inner(e.value, e.length);
        return readBerTlv(inner, out);
    }
    return false;
}

size_t offsetOf(const Context &ctx, const uint8_t *p) { return ctx.offsetOf(reinterpret_cast<const char *>(p)); }

std::string mechList(const std::vector<std::string> &oids) {
    std::string out;
    for (const auto &o: oids) out += (out.empty() ? "" : ", ") + gssMechanismName(o);
    return out;
}

void adopt(SecurityBlob &outer, const SecurityBlob &inner) {
    if (inner.hasKerberos) { outer.hasKerberos = true; outer.kerberos = inner.kerberos; }
    if (inner.hasNtlmssp) { outer.hasNtlmssp = true; outer.ntlmssp = inner.ntlmssp; outer.ntlmsspLength = inner.ntlmsspLength; }
}

void appendSummary(SecurityBlob &b, const SecurityBlob &inner) {
    if (!inner.ok) return;
    b.summary += " > " + inner.summary;
}

} // namespace

std::string gssMechanismName(const std::string &oid) {
    if (oid == kSpnego) return "SPNEGO";
    if (oid == "1.2.840.113554.1.2.2") return "Kerberos 5";
    if (oid == "1.2.840.48018.1.2.2") return "Kerberos 5 (MS)";
    if (oid == "1.2.840.113554.1.2.2.3") return "Kerberos 5 user-to-user";
    if (oid == "1.3.6.1.4.1.311.2.2.10") return "NTLMSSP";
    if (oid == "1.3.6.1.5.2.5") return "IAKerb";
    if (oid == "1.3.6.1.4.1.311.2.2.30") return "NEGOEX";
    return oid.empty() ? "unknown" : oid;
}

SecurityBlob decodeSecurityBlob(Context &ctx, const uint8_t *blob, size_t length, Field *parent, int depth) {
    SecurityBlob b;
    if (!blob || length < 2 || depth > 3) return b;
    const bool tree = parent && ctx.wantFields();
    auto add = [&](Field &under, const std::string &label, const uint8_t *at, size_t len) -> Field & {
        return under.add(label, offsetOf(ctx, at), len);
    };

    // NTLMSSP: located here, decoded by the protocol that carries it
    if (length >= 8 && std::memcmp(blob, "NTLMSSP\0", 8) == 0) {
        const uint32_t type = length >= 12 ? static_cast<uint32_t>(blob[8]) | (static_cast<uint32_t>(blob[9]) << 8) | (static_cast<uint32_t>(blob[10]) << 16) | (static_cast<uint32_t>(blob[11]) << 24) : 0;
        b.ok = b.hasNtlmssp = true;
        b.ntlmssp = blob;
        b.ntlmsspLength = length;
        b.kind = type == 1 ? "NTLMSSP_NEGOTIATE" : type == 2 ? "NTLMSSP_CHALLENGE" : type == 3 ? "NTLMSSP_AUTH" : "NTLMSSP";
        b.summary = b.kind;
        if (tree) add(*parent, "NTLMSSP (" + std::to_string(length) + " bytes): " + b.kind, blob, length);
        return b;
    }

    // Kerberos Wrap (05 04) / MIC (04 04) token after the context is established (RFC 4121 4.2.6)
    if ((blob[0] == 0x05 || blob[0] == 0x04) && blob[1] == 0x04) {
        b.ok = true;
        b.kind = blob[0] == 0x05 ? "GSS-API Kerberos Wrap token" : "GSS-API Kerberos MIC token";
        b.summary = b.kind;
        if (tree) add(*parent, b.kind + " (" + std::to_string(length) + " bytes, protected)", blob, length);
        return b;
    }

    BerTlv top;
    ByteReader r(blob, length);
    if (!readBerTlv(r, top) || !top.constructed || !top.value) return b;

    // a bare Kerberos message
    if (top.tagClass == asn1::Application && (top.tagNumber == 14 || top.tagNumber == 15 || top.tagNumber == 30)) {
        Field *k = tree ? &add(*parent, "Kerberos", blob, top.total) : nullptr;
        b.kerberos = decodeKerberosMessage(ctx, blob, length, k, depth);
        if (!b.kerberos.tagOk) return b;
        b.ok = b.hasKerberos = true;
        b.kind = "Kerberos " + b.kerberos.typeName;
        b.summary = b.kerberos.info;
        return b;
    }

    // GSS-API InitialContextToken: [APPLICATION 0] { thisMech OID, token }
    if (top.isApplication(0)) {
        ByteReader tr(top.value, top.length);
        BerTlv oid;
        if (!readBerTlv(tr, oid) || !oid.isUniversal(asn1::tag::Oid)) return b;
        b.mech = oid.asOid();
        const uint8_t *tok = top.value + oid.total;
        const size_t tokLen = top.length - oid.total;
        const std::string mechName = gssMechanismName(b.mech);
        b.ok = true;
        b.kind = "GSS-API " + mechName;
        Field *g = tree ? &add(*parent, "GSS-API Generic Security Service Application Program Interface", blob, top.total) : nullptr;
        if (g) add(*g, "OID: " + b.mech + " (" + mechName + ")", top.value, oid.total);

        if (b.mech == kSpnego) {
            const SecurityBlob inner = decodeSecurityBlob(ctx, tok, tokLen, g, depth + 1);
            if (!inner.ok) { b.summary = "GSS-API SPNEGO"; return b; }
            adopt(b, inner);
            b.kind = inner.kind;
            b.offeredMechs = inner.offeredMechs;
            b.negState = inner.negState;
            b.mechToken = inner.mechToken;
            b.mechTokenLength = inner.mechTokenLength;
            b.summary = inner.summary;
            return b;
        }
        if (isKerberosMech(b.mech) && tokLen >= 2) {
            const unsigned tokId = (static_cast<unsigned>(tok[0]) << 8) | tok[1];
            const char *tokName = tokId == 0x0100 ? "AP-REQ" : tokId == 0x0200 ? "AP-REP" : tokId == 0x0300 ? "KRB-ERROR" : tokId == 0x0400 ? "TGT-REQ" : tokId == 0x0500 ? "TGT-REP" : nullptr;
            if (g) add(*g, std::string("krb5_tok_id: ") + (tokName ? tokName : "unknown") + " (" + hexString(tokId, 4) + ")", tok, 2);
            if (tokId == 0x0100 || tokId == 0x0200 || tokId == 0x0300) {
                Field *k = g ? &add(*g, "Kerberos", tok + 2, tokLen - 2) : nullptr;
                b.kerberos = decodeKerberosMessage(ctx, tok + 2, tokLen - 2, k, depth);
                if (b.kerberos.tagOk) {
                    b.hasKerberos = true;
                    b.kind = "GSS-API Kerberos 5 " + b.kerberos.typeName;
                    b.summary = b.kerberos.info;
                    return b;
                }
            }
            b.kind = std::string("GSS-API Kerberos 5") + (tokName ? std::string(" ") + tokName : "");
        }
        b.summary = b.kind;
        return b;
    }

    // NegotiationToken: negTokenInit [0] / negTokenResp [1]
    if ((top.isContext(0) || top.isContext(1)) && top.value) {
        ByteReader sr(top.value, top.length);
        BerTlv seq;
        if (!readBerTlv(sr, seq) || !seq.isUniversal(asn1::tag::Sequence)) return b;
        const bool init = top.isContext(0);
        b.ok = true;
        b.kind = init ? "SPNEGO NegTokenInit" : "SPNEGO NegTokenResp";
        Field *n = tree ? &add(*parent, "Simple Protected Negotiation: " + std::string(init ? "negTokenInit" : "negTokenResp"), blob, top.total) : nullptr;
        BerTlv v;
        const uint8_t *tokenAt = nullptr;
        size_t tokenLen = 0;
        if (init) {
            if (child(seq, 0, v) && v.constructed) {
                ByteReader mr(v.value, v.length);
                BerTlv m;
                int count = 0;
                while (mr.remaining() > 0 && readBerTlv(mr, m) && count++ < 16) if (m.isUniversal(asn1::tag::Oid)) b.offeredMechs.push_back(m.asOid());
                if (n) {
                    Field &list = add(*n, "mechTypes (" + std::to_string(b.offeredMechs.size()) + "): " + mechList(b.offeredMechs), v.value - v.headerLength, v.total);
                    ByteReader lr(v.value, v.length);
                    int c2 = 0;
                    while (lr.remaining() > 0 && readBerTlv(lr, m) && c2++ < 16) if (m.isUniversal(asn1::tag::Oid)) add(list, m.asOid() + " (" + gssMechanismName(m.asOid()) + ")", m.value - m.headerLength, m.total);
                }
            }
            if (child(seq, 2, v) && v.isUniversal(asn1::tag::OctetString)) { tokenAt = v.value; tokenLen = v.length; }
        } else {
            if (child(seq, 0, v)) {
                int64_t st = -1;
                if (v.asInt64(st)) {
                    static const char *names[] = {"accept-completed", "accept-incomplete", "reject", "request-mic"};
                    b.negState = st >= 0 && st < 4 ? names[st] : "unknown";
                    if (n) add(*n, "negState: " + b.negState + " (" + std::to_string(st) + ")", v.value - v.headerLength, v.total);
                }
            }
            if (child(seq, 1, v) && v.isUniversal(asn1::tag::Oid)) {
                b.mech = v.asOid();
                if (n) add(*n, "supportedMech: " + b.mech + " (" + gssMechanismName(b.mech) + ")", v.value - v.headerLength, v.total);
            }
            if (child(seq, 2, v) && v.isUniversal(asn1::tag::OctetString)) { tokenAt = v.value; tokenLen = v.length; }
        }
        b.summary = b.kind;
        if (init && !b.offeredMechs.empty()) b.summary += " [" + mechList(b.offeredMechs) + "]";
        if (!init && !b.negState.empty()) b.summary += " " + b.negState;
        if (tokenAt && tokenLen > 0) {
            b.mechToken = tokenAt;
            b.mechTokenLength = tokenLen;
            Field *t = n ? &add(*n, std::string(init ? "mechToken" : "responseToken") + " (" + std::to_string(tokenLen) + " bytes)", tokenAt, tokenLen) : nullptr;
            const SecurityBlob inner = decodeSecurityBlob(ctx, tokenAt, tokenLen, t, depth + 1);
            adopt(b, inner);
            appendSummary(b, inner);
        }
        if (child(seq, 3, v) && n) add(*n, "mechListMIC (" + std::to_string(v.length) + " bytes)", v.value - v.headerLength, v.total);
        return b;
    }
    return b;
}

} // namespace dissect

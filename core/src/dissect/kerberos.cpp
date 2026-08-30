// Kerberos 5 (RFC 4120). Context tags follow the ASN.1 of section 5 per message type:
//   KDC-REQ   pvno [1] msg-type [2] padata [3] req-body [4]      (AS-REQ [APPLICATION 10], TGS-REQ [12])
//   KDC-REP   pvno [0] msg-type [1] padata [2] crealm [3] cname [4] ticket [5] enc-part [6]   (AS-REP [11], TGS-REP [13])
//   AP-REQ    pvno [0] msg-type [1] ap-options [2] ticket [3] authenticator [4]               ([14])
//   AP-REP    pvno [0] msg-type [1] enc-part [2]                                              ([15])
//   KRB-ERROR pvno [0] msg-type [1] ctime [2] cusec [3] stime [4] susec [5] error-code [6] crealm [7] cname [8]
//             realm [9] sname [10] e-text [11] e-data [12]                                    ([30])
//   KDC-REQ-BODY kdc-options [0] cname [1] realm [2] sname [3] from [4] till [5] rtime [6] nonce [7] etype [8] ...
//   Ticket ([APPLICATION 1]) tkt-vno [0] realm [1] sname [2] enc-part [3]
#include "kerberos.h"

#include <string>
#include <vector>

#include "asn1.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxMessage = 8u << 20;   // not more than the stream table buffers

const char *kerberosMsgTypeName(int64_t msgType) {
    switch (msgType) {
        case 1: return "Ticket";
        case 10: return "AS-REQ";
        case 11: return "AS-REP";
        case 12: return "TGS-REQ";
        case 13: return "TGS-REP";
        case 14: return "AP-REQ";
        case 15: return "AP-REP";
        case 20: return "KRB-SAFE";
        case 21: return "KRB-PRIV";
        case 22: return "KRB-CRED";
        case 30: return "KRB-ERROR";
        default: return nullptr;
    }
}

// RFC 4120 7.5.9, RFC 6113 and RFC 4556 (PKINIT) error codes
const char *kerberosErrorCodeName(int64_t err) {
    switch (err) {
        case 0: return "KDC_ERR_NONE";
        case 1: return "KDC_ERR_NAME_EXP";
        case 2: return "KDC_ERR_SERVICE_EXP";
        case 3: return "KDC_ERR_BAD_PVNO";
        case 4: return "KDC_ERR_C_OLD_MAST_KVNO";
        case 5: return "KDC_ERR_S_OLD_MAST_KVNO";
        case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
        case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
        case 8: return "KDC_ERR_PRINCIPAL_NOT_UNIQUE";
        case 9: return "KDC_ERR_NULL_KEY";
        case 10: return "KDC_ERR_CANNOT_POSTDATE";
        case 11: return "KDC_ERR_NEVER_VALID";
        case 12: return "KDC_ERR_POLICY";
        case 13: return "KDC_ERR_BADOPTION";
        case 14: return "KDC_ERR_ETYPE_NOSUPP";
        case 15: return "KDC_ERR_SUMTYPE_NOSUPP";
        case 16: return "KDC_ERR_PADATA_TYPE_NOSUPP";
        case 17: return "KDC_ERR_TRTYPE_NOSUPP";
        case 18: return "KDC_ERR_CLIENT_REVOKED";
        case 19: return "KDC_ERR_SERVICE_REVOKED";
        case 20: return "KDC_ERR_TGT_REVOKED";
        case 21: return "KDC_ERR_CLIENT_NOTYET";
        case 22: return "KDC_ERR_SERVICE_NOTYET";
        case 23: return "KDC_ERR_KEY_EXPIRED";
        case 24: return "KDC_ERR_PREAUTH_FAILED";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED";
        case 26: return "KDC_ERR_SERVER_NOMATCH";
        case 27: return "KDC_ERR_MUST_USE_USER2USER";
        case 28: return "KDC_ERR_PATH_NOT_ACCEPTED";
        case 29: return "KDC_ERR_SVC_UNAVAILABLE";
        case 31: return "KRB_AP_ERR_BAD_INTEGRITY";
        case 32: return "KRB_AP_ERR_TKT_EXPIRED";
        case 33: return "KRB_AP_ERR_TKT_NYV";
        case 34: return "KRB_AP_ERR_REPEAT";
        case 35: return "KRB_AP_ERR_NOT_US";
        case 36: return "KRB_AP_ERR_BADMATCH";
        case 37: return "KRB_AP_ERR_SKEW";
        case 38: return "KRB_AP_ERR_BADADDR";
        case 39: return "KRB_AP_ERR_BADVERSION";
        case 40: return "KRB_AP_ERR_MSG_TYPE";
        case 41: return "KRB_AP_ERR_MODIFIED";
        case 42: return "KRB_AP_ERR_BADORDER";
        case 44: return "KRB_AP_ERR_BADKEYVER";
        case 45: return "KRB_AP_ERR_NOKEY";
        case 46: return "KRB_AP_ERR_MUT_FAIL";
        case 47: return "KRB_AP_ERR_BADDIRECTION";
        case 48: return "KRB_AP_ERR_METHOD";
        case 49: return "KRB_AP_ERR_BADSEQ";
        case 50: return "KRB_AP_ERR_INAPP_CKSUM";
        case 51: return "KRB_AP_PATH_NOT_ACCEPTED";
        case 52: return "KRB_ERR_RESPONSE_TOO_BIG";
        case 60: return "KRB_ERR_GENERIC";
        case 61: return "KRB_ERR_FIELD_TOOLONG";
        case 62: return "KDC_ERROR_CLIENT_NOT_TRUSTED";
        case 63: return "KDC_ERROR_KDC_NOT_TRUSTED";
        case 64: return "KDC_ERROR_INVALID_SIG";
        case 65: return "KDC_ERR_KEY_TOO_WEAK";
        case 66: return "KDC_ERR_CERTIFICATE_MISMATCH";
        case 67: return "KRB_AP_ERR_NO_TGT";
        case 68: return "KDC_ERR_WRONG_REALM";
        case 69: return "KRB_AP_ERR_USER_TO_USER_REQUIRED";
        case 70: return "KDC_ERR_CANT_VERIFY_CERTIFICATE";
        case 71: return "KDC_ERR_INVALID_CERTIFICATE";
        case 72: return "KDC_ERR_REVOKED_CERTIFICATE";
        case 73: return "KDC_ERR_REVOCATION_STATUS_UNKNOWN";
        case 74: return "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE";
        case 75: return "KDC_ERR_CLIENT_NAME_MISMATCH";
        case 76: return "KDC_ERR_KDC_NAME_MISMATCH";
        case 90: return "KDC_ERR_PREAUTH_EXPIRED";
        case 91: return "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED";
        case 92: return "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET";
        case 93: return "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION";
        default: return nullptr;
    }
}

// Pre-authentication data types (IANA "Kerberos Pre-authentication and Typed Data")
const char *paDataTypeName(int64_t t) {
    switch (t) {
        case 1: return "PA-TGS-REQ";
        case 2: return "PA-ENC-TIMESTAMP";
        case 3: return "PA-PW-SALT";
        case 11: return "PA-ETYPE-INFO";
        case 14: return "PA-PK-AS-REQ-OLD";
        case 15: return "PA-PK-AS-REP-OLD";
        case 16: return "PA-PK-AS-REQ";
        case 17: return "PA-PK-AS-REP";
        case 19: return "PA-ETYPE-INFO2";
        case 20: return "PA-SVR-REFERRAL-INFO";
        case 128: return "PA-PAC-REQUEST";
        case 129: return "PA-FOR-USER";
        case 130: return "PA-FOR-X509-USER";
        case 131: return "PA-FOR-CHECK-DUPS";
        case 132: return "PA-AS-CHECKSUM";
        case 133: return "PA-FX-COOKIE";
        case 134: return "PA-AUTHENTICATION-SET";
        case 135: return "PA-AUTH-SET-SELECTED";
        case 136: return "PA-FX-FAST";
        case 137: return "PA-FX-ERROR";
        case 138: return "PA-ENCRYPTED-CHALLENGE";
        case 149: return "PA-S4U-X509-USER";
        case 165: return "PA-SUPPORTED-ENCTYPES";
        case 166: return "PA-EXTENDED-ERROR";
        case 167: return "PA-PAC-OPTIONS";
        default: return nullptr;
    }
}

const char *etypeName(int64_t t) {
    switch (t) {
        case 1: return "des-cbc-crc";
        case 2: return "des-cbc-md4";
        case 3: return "des-cbc-md5";
        case 16: return "des3-cbc-sha1";
        case 17: return "aes128-cts-hmac-sha1-96";
        case 18: return "aes256-cts-hmac-sha1-96";
        case 19: return "aes128-cts-hmac-sha256-128";
        case 20: return "aes256-cts-hmac-sha384-192";
        case 23: return "rc4-hmac";
        case 24: return "rc4-hmac-exp";
        case 25: return "camellia128-cts-cmac";
        case 26: return "camellia256-cts-cmac";
        default: return nullptr;
    }
}

const char *nameTypeName(int64_t t) {
    switch (t) {
        case 0: return "NT-UNKNOWN";
        case 1: return "NT-PRINCIPAL";
        case 2: return "NT-SRV-INST";
        case 3: return "NT-SRV-HST";
        case 4: return "NT-SRV-XHST";
        case 5: return "NT-UID";
        case 6: return "NT-X500-PRINCIPAL";
        case 7: return "NT-SMTP-NAME";
        case 10: return "NT-ENTERPRISE";
        default: return nullptr;
    }
}

std::string named(const char *name, int64_t v) { return std::string(name ? name : "unknown") + " (" + std::to_string(v) + ")"; }

std::string text(const BerTlv &t) { return printableText(t.value, t.length); }

// The TLV inside the EXPLICIT context tag [n] of a SEQUENCE; `outer` (optional) is the [n] element itself.
bool ctxChild(const BerTlv &seq, uint32_t n, BerTlv &out, BerTlv *outer = nullptr) {
    if (!seq.constructed || !seq.value) return false;
    ByteReader r(seq.value, seq.length);
    BerTlv e;
    while (r.remaining() > 0 && readBerTlv(r, e)) {
        if (!e.isContext(n)) continue;
        if (outer) *outer = e;
        ByteReader inner(e.value, e.length);
        return readBerTlv(inner, out);
    }
    return false;
}

bool ctxInt(const BerTlv &seq, uint32_t n, int64_t &v) {
    BerTlv t;
    return ctxChild(seq, n, t) && t.asInt64(v);
}

// PrincipalName: name-type [0], name-string [1] SEQUENCE OF KerberosString -> "a/b"
std::string principal(const BerTlv &pn, int64_t *nameType = nullptr) {
    std::string out;
    BerTlv t, strings;
    if (nameType) *nameType = -1;
    if (nameType) ctxInt(pn, 0, *nameType);
    if (!ctxChild(pn, 1, strings)) return out;
    ByteReader r(strings.value, strings.length);
    int n = 0;
    while (r.remaining() > 0 && readBerTlv(r, t) && n++ < 16) {
        if (!out.empty()) out += "/";
        out += text(t);
    }
    return out;
}

struct PaData {
    int64_t type = 0;
    BerTlv element;   // the PA-DATA SEQUENCE
};

// SEQUENCE OF PA-DATA (the TLV is the SEQUENCE)
std::vector<PaData> paDataList(const BerTlv &seqOf) {
    std::vector<PaData> out;
    ByteReader r(seqOf.value, seqOf.length);
    BerTlv e;
    while (seqOf.constructed && r.remaining() > 0 && readBerTlv(r, e) && out.size() < 32) {
        PaData pa;
        pa.element = e;
        if (ctxInt(e, 1, pa.type)) out.push_back(pa);
    }
    return out;
}

std::string paNames(const std::vector<PaData> &list) {
    std::string out;
    for (const auto &pa: list) {
        if (!out.empty()) out += ",";
        const char *n = paDataTypeName(pa.type);
        out += n ? std::string(n) : "PA-" + std::to_string(pa.type);
    }
    return out;
}

size_t offsetOfTlv(const Context &ctx, const BerTlv &t) { return ctx.offsetOf(reinterpret_cast<const char *>(t.value)) - t.headerLength; }

Field &node(Context &ctx, Field &parent, const std::string &label, const BerTlv &t) {
    return parent.add(label, offsetOfTlv(ctx, t), t.total);
}

// Checksum types (RFC 3961, RFC 3962, RFC 4757)
const char *checksumTypeName(int64_t t) {
    switch (t) {
        case 1: return "crc32";
        case 2: return "rsa-md4";
        case 4: return "rsa-md5";
        case 8: return "rsa-md5-des";
        case 12: return "hmac-sha1-des3";
        case 15: return "hmac-sha1-96-aes128";
        case 16: return "hmac-sha1-96-aes256";
        case 19: return "cmac-camellia128";
        case 20: return "cmac-camellia256";
        case -138: return "hmac-md5";
        default: return nullptr;
    }
}

struct FlagName {
    int bit;   // RFC 4120 5.2.8: bit 0 is the most significant of the 32
    const char *name;
};

std::string flagList(uint32_t value, const FlagName *names, size_t count) {
    std::string out;
    for (size_t i = 0; i < count; ++i) {
        if (!(value & (0x80000000u >> names[i].bit))) continue;
        if (!out.empty()) out += ", ";
        out += names[i].name;
    }
    return out;
}

// KDCOptions (RFC 4120 5.4.1)
std::string kdcOptionNames(uint32_t v) {
    static const FlagName names[] = {{1, "forwardable"}, {2, "forwarded"}, {3, "proxiable"}, {4, "proxy"}, {5, "allow-postdate"},
        {6, "postdated"}, {8, "renewable"}, {14, "request-anonymous"}, {15, "canonicalize"}, {26, "disable-transited-check"},
        {27, "renewable-ok"}, {28, "enc-tkt-in-skey"}, {30, "renew"}, {31, "validate"}};
    return flagList(v, names, sizeof names / sizeof *names);
}

// APOptions (RFC 4120 5.5.1)
std::string apOptionNames(uint32_t v) {
    static const FlagName names[] = {{1, "use-session-key"}, {2, "mutual-required"}};
    return flagList(v, names, sizeof names / sizeof *names);
}

// BIT STRING of 32 flags: first content byte is the number of unused bits, then the bytes, most significant first
bool flags32(const BerTlv &bits, uint32_t &out) {
    if (!bits.isUniversal(asn1::tag::BitString) || !bits.value || bits.length < 2) return false;
    out = 0;
    for (size_t i = 1; i < bits.length && i <= 4; ++i) out |= static_cast<uint32_t>(bits.value[i]) << (8 * (4 - i));
    return true;
}

// EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] OCTET STRING }: the cipher is never decoded
void addEncryptedData(Context &ctx, Field &parent, const std::string &label, const BerTlv &enc) {
    int64_t et = 0, kvno = 0;
    BerTlv cipher;
    Field &e = node(ctx, parent, label, enc);
    if (ctxInt(enc, 0, et)) e.add("etype: " + named(etypeName(et), et));
    if (ctxInt(enc, 1, kvno)) e.add("kvno: " + std::to_string(kvno));
    if (ctxChild(enc, 2, cipher)) node(ctx, e, "cipher: " + std::to_string(cipher.length) + " bytes (encrypted)", cipher);
}

// Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }
void addTicket(Context &ctx, Field &parent, const BerTlv &ticketApp) {
    BerTlv seq;
    ByteReader r(ticketApp.value, ticketApp.length);
    Field &t = node(ctx, parent, "ticket", ticketApp);
    if (!readBerTlv(r, seq)) return;
    BerTlv v;
    int64_t vno = 0;
    if (ctxInt(seq, 0, vno)) t.add("tkt-vno: " + std::to_string(vno));
    if (ctxChild(seq, 1, v)) node(ctx, t, "realm: " + text(v), v);
    if (ctxChild(seq, 2, v)) node(ctx, t, "sname: " + principal(v), v);
    BerTlv enc;
    if (ctxChild(seq, 3, enc)) addEncryptedData(ctx, t, "enc-part", enc);
}

void addPrincipal(Context &ctx, Field &parent, const char *label, const BerTlv &pn) {
    int64_t nt = -1;
    const std::string n = principal(pn, &nt);
    Field &c = node(ctx, parent, std::string(label) + ": " + n, pn);
    if (nt >= 0) c.add("name-type: " + named(nameTypeName(nt), nt));
}

// Checksum ::= SEQUENCE { cksumtype [0], checksum [1] OCTET STRING }
void addChecksum(Context &ctx, Field &parent, const BerTlv &ck) {
    int64_t ct = 0;
    BerTlv sum;
    Field &c = node(ctx, parent, "cksum", ck);
    if (ctxInt(ck, 0, ct)) c.add("cksumtype: " + named(checksumTypeName(ct), ct));
    if (ctxChild(ck, 1, sum)) node(ctx, c, "checksum: " + std::to_string(sum.length) + " bytes", sum);
}

// The padata-value of a few PA-DATA types is decoded further: it is itself a Kerberos structure
void addPaDataValue(Context &ctx, Field &n, const PaData &pa, int depth) {
    BerTlv val, inner;
    if (!ctxChild(pa.element, 2, val) || !val.isUniversal(asn1::tag::OctetString)) return;
    ByteReader vr(val.value, val.length);
    switch (pa.type) {
        case 1: // PA-TGS-REQ: an AP-REQ
            if (depth < 2 && val.length > 0) {
                Field &k = n.add("Kerberos", ctx.offsetOf(reinterpret_cast<const char *>(val.value)), val.length);
                decodeKerberosMessage(ctx, val.value, val.length, &k, depth + 1);
            }
            break;
        case 2: // PA-ENC-TIMESTAMP: EncryptedData
            if (readBerTlv(vr, inner)) addEncryptedData(ctx, n, "PA-ENC-TS-ENC", inner);
            break;
        case 19: { // PA-ETYPE-INFO2: SEQUENCE OF ETYPE-INFO2-ENTRY { etype [0], salt [1] KerberosString OPTIONAL, s2kparams [2] }
            if (!readBerTlv(vr, inner) || !inner.constructed) break;
            ByteReader er(inner.value, inner.length);
            BerTlv entry, salt;
            int count = 0;
            while (er.remaining() > 0 && readBerTlv(er, entry) && count++ < 16) {
                int64_t et = 0;
                if (!ctxInt(entry, 0, et)) continue;
                std::string label = "ETYPE-INFO2: " + named(etypeName(et), et);
                if (ctxChild(entry, 1, salt)) label += " salt=" + text(salt);
                node(ctx, n, label, entry);
            }
            break;
        }
        case 128: { // PA-PAC-REQUEST: SEQUENCE { include-pac [0] BOOLEAN }
            BerTlv b;
            if (readBerTlv(vr, inner) && ctxChild(inner, 0, b) && b.length > 0) n.add(std::string("include-pac: ") + (b.value[0] ? "true" : "false"), offsetOfTlv(ctx, b), b.total);
            break;
        }
        default: break;
    }
}

void addPaData(Context &ctx, Field &parent, const std::vector<PaData> &list, const BerTlv &seqOf, int depth) {
    Field &p = node(ctx, parent, "padata (" + std::to_string(list.size()) + ")", seqOf);
    for (const auto &pa: list) {
        const char *n = paDataTypeName(pa.type);
        Field &f = node(ctx, p, "PA-DATA " + named(n ? n : "unknown", pa.type), pa.element);
        addPaDataValue(ctx, f, pa, depth);
    }
}

} // namespace

StreamFrame frameKerberos(const char *data, size_t length) {
    if (length < 4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // RFC 4120 7.2.2: a 4 byte length, high bit reserved (zero)
    const uint32_t pduLen = (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
                            (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
    if (pduLen == 0 || pduLen > kMaxMessage) return StreamFrame{StreamFrame::Kind::Reject, 0};
    // the message is an [APPLICATION n] constructed element
    if (length > 4 && (bytes[4] & 0xe0) != 0x60) return StreamFrame{StreamFrame::Kind::Reject, 0};
    const size_t total = 4 + static_cast<size_t>(pduLen);
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

KerberosSummary decodeKerberosMessage(Context &ctx, const uint8_t *msg, size_t msgAvail, Field *root, int depth) {
    KerberosSummary s;
    if (msgAvail < 2 || (msg[0] & 0xe0) != 0x60 || (msg[0] & 0x1f) == 0x1f) return s;
    const uint32_t appTag = msg[0] & 0x1f;
    size_t appHeader = 2, appBody = msg[1];
    if (msg[1] >= 0x80) {
        const size_t count = msg[1] & 0x7f;
        if (count == 0 || count > 4 || msgAvail < 2 + count) return s;
        appBody = 0;
        for (size_t i = 0; i < count; ++i) appBody = (appBody << 8) | msg[2 + i];
        appHeader = 2 + count;
    }
    s.tagOk = true;
    s.cut = appHeader + appBody > msgAvail;   // a segment of a longer message, or a cut capture
    s.length = std::min(msgAvail, appHeader + appBody);
    const char *typeName = kerberosMsgTypeName(appTag);
    s.appTag = appTag;

    int64_t msgType = appTag;
    BerTlv app;
    ByteReader ar(msg, msgAvail);
    const bool appOk = !s.cut && readBerTlv(ar, app);
    BerTlv body;
    bool haveBody = false;
    if (appOk) {
        ByteReader br(app.value, app.length);
        haveBody = readBerTlv(br, body) && body.isUniversal(asn1::tag::Sequence);
    }
    s.bodyOk = appOk && haveBody;

    int64_t innerType = 0;
    BerTlv t;
    BerTlv reqBody;
    std::string cnameText, snameText, crealmText, realmText, etext;
    BerTlv ticket, authenticator, encPart, ctime, stime, edata, apOptions, safeBody, cksum, tickets;
    bool haveTicket = false, haveEnc = false, haveReqBody = false, haveEdata = false;
    std::vector<PaData> padata;
    BerTlv padataSeq;
    bool havePadata = false;
    int64_t pvno = 0;
    int64_t susec = -1;
    int64_t errorCode = -1;

    if (haveBody) {
        const bool isReq = appTag == 10 || appTag == 12, isRep = appTag == 11 || appTag == 13;
        const uint32_t tagPvno = isReq ? 1 : 0, tagMsg = isReq ? 2 : 1;
        ctxInt(body, tagPvno, pvno);
        if (ctxInt(body, tagMsg, innerType)) msgType = innerType;
        if (isReq) {
            if (ctxChild(body, 3, padataSeq)) { padata = paDataList(padataSeq); havePadata = true; }
            if (ctxChild(body, 4, reqBody) && reqBody.isUniversal(asn1::tag::Sequence)) {
                haveReqBody = true;
                if (ctxChild(reqBody, 1, t)) cnameText = principal(t);
                if (ctxChild(reqBody, 2, t)) realmText = text(t);
                if (ctxChild(reqBody, 3, t)) snameText = principal(t);
            }
        } else if (isRep) {
            if (ctxChild(body, 2, padataSeq)) { padata = paDataList(padataSeq); havePadata = true; }
            if (ctxChild(body, 3, t)) crealmText = text(t);
            if (ctxChild(body, 4, t)) cnameText = principal(t);
            if (ctxChild(body, 5, ticket)) haveTicket = true;
            if (ctxChild(body, 6, encPart)) haveEnc = true;
            realmText = crealmText;
        } else if (appTag == 14) {
            ctxChild(body, 2, apOptions);
            if (ctxChild(body, 3, ticket)) haveTicket = true;
            if (ctxChild(body, 4, authenticator)) haveEnc = true;
            if (haveTicket) {   // the service the ticket is for
                ByteReader tr(ticket.value, ticket.length);
                BerTlv tseq;
                if (readBerTlv(tr, tseq)) {
                    if (ctxChild(tseq, 1, t)) realmText = text(t);
                    if (ctxChild(tseq, 2, t)) snameText = principal(t);
                }
            }
        } else if (appTag == 15) {
            if (ctxChild(body, 2, encPart)) haveEnc = true;
        } else if (appTag == 20) { // KRB-SAFE: safe-body [2], cksum [3]
            ctxChild(body, 2, safeBody);
            ctxChild(body, 3, cksum);
        } else if (appTag == 21) { // KRB-PRIV: enc-part [3]
            if (ctxChild(body, 3, encPart)) haveEnc = true;
        } else if (appTag == 22) { // KRB-CRED: tickets [2] SEQUENCE OF Ticket, enc-part [3]
            ctxChild(body, 2, tickets);
            if (ctxChild(body, 3, encPart)) haveEnc = true;
        } else if (appTag == 30) {
            ctxInt(body, 6, errorCode);
            ctxInt(body, 5, susec);
            if (ctxChild(body, 7, t)) crealmText = text(t);
            if (ctxChild(body, 8, t)) cnameText = principal(t);
            if (ctxChild(body, 9, t)) realmText = text(t);
            if (ctxChild(body, 10, t)) snameText = principal(t);
            if (ctxChild(body, 11, t)) etext = text(t);
            if (ctxChild(body, 12, edata)) haveEdata = true;
            // e-data of KDC_ERR_PREAUTH_REQUIRED (and the like) is METHOD-DATA ::= SEQUENCE OF PA-DATA
            if (haveEdata && edata.isUniversal(asn1::tag::OctetString)) {
                ByteReader er(edata.value, edata.length);
                BerTlv md;
                if (readBerTlv(er, md) && md.isUniversal(asn1::tag::Sequence)) {
                    padataSeq = md;
                    padata = paDataList(md);
                    havePadata = !padata.empty();
                }
            }
            ctxChild(body, 2, ctime);
            ctxChild(body, 4, stime);
        }
    }
    const char *innerName = kerberosMsgTypeName(msgType);
    const std::string typeStr = innerName ? innerName : typeName ? typeName : "Kerberos";

    std::string summary = typeStr;
    if (errorCode >= 0) {
        const char *en = kerberosErrorCodeName(errorCode);
        summary += " " + std::string(en ? en : "error") + " (" + std::to_string(errorCode) + ")";
    }
    if (!cnameText.empty()) summary += " cname=" + cnameText;
    if (!snameText.empty()) summary += " sname=" + snameText;
    if (!realmText.empty()) summary += " realm=" + realmText;
    if (havePadata && !padata.empty()) summary += " padata=" + paNames(padata);
    s.msgType = msgType;
    s.errorCode = errorCode;
    s.typeName = typeStr;
    s.cname = cnameText;
    s.sname = snameText;
    s.crealm = crealmText;
    s.realm = realmText;
    s.info = summary;

    if (root && ctx.wantFields()) {
        root->text = "Kerberos (" + typeStr + ")";
        root->length = static_cast<uint32_t>(s.length);
        if (haveBody) {
            if (pvno > 0) root->add("pvno: " + std::to_string(pvno));
            root->add("msg-type: " + named(innerName ? innerName : typeName, msgType));
            if (havePadata && appTag != 30) addPaData(ctx, *root, padata, padataSeq, depth);
            if (appTag == 14) {
                uint32_t o = 0;
                if (flags32(apOptions, o)) {
                    const std::string names = apOptionNames(o);
                    node(ctx, *root, "ap-options: " + hexString(o, 8) + (names.empty() ? "" : " (" + names + ")"), apOptions);
                }
            }
            if (haveReqBody) {
                Field &b = node(ctx, *root, "req-body", reqBody);
                BerTlv v;
                uint32_t o = 0;
                if (ctxChild(reqBody, 0, v) && flags32(v, o)) {
                    const std::string names = kdcOptionNames(o);
                    node(ctx, b, "kdc-options: " + hexString(o, 8) + (names.empty() ? "" : " (" + names + ")"), v);
                }
                if (ctxChild(reqBody, 1, v)) addPrincipal(ctx, b, "cname", v);
                if (ctxChild(reqBody, 2, v)) node(ctx, b, "realm: " + text(v), v);
                if (ctxChild(reqBody, 3, v)) addPrincipal(ctx, b, "sname", v);
                if (ctxChild(reqBody, 4, v)) node(ctx, b, "from: " + text(v), v);
                if (ctxChild(reqBody, 5, v)) node(ctx, b, "till: " + text(v), v);
                if (ctxChild(reqBody, 6, v)) node(ctx, b, "rtime: " + text(v), v);
                int64_t nonce = 0;
                if (ctxInt(reqBody, 7, nonce)) b.add("nonce: " + std::to_string(nonce));
                if (ctxChild(reqBody, 8, v)) {
                    Field &e = node(ctx, b, "etype", v);
                    ByteReader er(v.value, v.length);
                    BerTlv et;
                    int n = 0;
                    while (er.remaining() > 0 && readBerTlv(er, et) && n++ < 32) {
                        int64_t x = 0;
                        if (et.asInt64(x)) node(ctx, e, "ENCTYPE: " + named(etypeName(x), x), et);
                    }
                }
                if (ctxChild(reqBody, 10, v)) addEncryptedData(ctx, b, "enc-authorization-data", v);
                if (ctxChild(reqBody, 11, v) && v.constructed) {   // additional-tickets: SEQUENCE OF Ticket
                    Field &a = node(ctx, b, "additional-tickets", v);
                    ByteReader tr(v.value, v.length);
                    BerTlv tk;
                    int n = 0;
                    while (tr.remaining() > 0 && readBerTlv(tr, tk) && n++ < 8) addTicket(ctx, a, tk);
                }
            }
            if (appTag == 11 || appTag == 13) {
                BerTlv v;
                if (ctxChild(body, 3, v)) node(ctx, *root, "crealm: " + text(v), v);
                if (ctxChild(body, 4, v)) addPrincipal(ctx, *root, "cname", v);
            }
            if (haveTicket) addTicket(ctx, *root, ticket);
            if (appTag == 22 && tickets.value && tickets.constructed) {
                Field &a = node(ctx, *root, "tickets", tickets);
                ByteReader tr(tickets.value, tickets.length);
                BerTlv tk;
                int n = 0;
                while (tr.remaining() > 0 && readBerTlv(tr, tk) && n++ < 16) addTicket(ctx, a, tk);
            }
            if (appTag == 20 && safeBody.value && safeBody.constructed) { // KRB-SAFE-BODY: user-data [0], timestamp [1], usec [2], seq-number [3]: integrity only, not encrypted
                Field &sb = node(ctx, *root, "safe-body", safeBody);
                BerTlv v;
                if (ctxChild(safeBody, 0, v)) node(ctx, sb, "user-data: " + std::to_string(v.length) + " bytes (integrity protected, not encrypted)", v);
                if (ctxChild(safeBody, 1, v)) node(ctx, sb, "timestamp: " + text(v), v);
                int64_t n = 0;
                if (ctxInt(safeBody, 3, n)) sb.add("seq-number: " + std::to_string(n));
                if (cksum.value && cksum.constructed) addChecksum(ctx, *root, cksum);
            }
            if (haveEnc) {
                const char *label = appTag == 14 ? "authenticator" : "enc-part";
                addEncryptedData(ctx, *root, label, appTag == 14 ? authenticator : encPart);
            }
            if (appTag == 30) {
                if (ctime.value) node(ctx, *root, "ctime: " + text(ctime), ctime);
                if (stime.value) node(ctx, *root, "stime: " + text(stime), stime);
                if (susec >= 0) root->add("susec: " + std::to_string(susec));
                const char *en = kerberosErrorCodeName(errorCode);
                if (errorCode >= 0) root->add("error-code: " + named(en ? en : "unknown error", errorCode));
                if (!crealmText.empty()) root->add("crealm: " + crealmText);
                if (!cnameText.empty()) root->add("cname: " + cnameText);
                if (!realmText.empty()) root->add("realm: " + realmText);
                if (!snameText.empty()) root->add("sname: " + snameText);
                if (!etext.empty()) root->add("e-text: " + etext);
                if (haveEdata) {
                    Field &e = node(ctx, *root, "e-data", edata);
                    if (havePadata) addPaData(ctx, e, padata, padataSeq, depth);
                }
            }
        } else if (appOk) {
            root->add("[the message body is not a SEQUENCE]");
        }
    }
    return s;
}

void dissectKerberos(Context &ctx, const char *data, size_t length) {
    if (!data || length == 0) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    // TCP: 4 byte record mark in front (its first byte is zero, a message starts with an APPLICATION tag 0x6a..0x7e)
    size_t mark = 0;
    if (length >= 5 && bytes[0] < 0x40) mark = 4;
    const uint8_t *msg = bytes + mark;
    const size_t msgAvail = length - mark;

    pack.protocol = "Kerberos";
    Field *root = nullptr;
    if (ctx.wantFields()) {
        root = &ctx.addLayer("Kerberos", ctx.offsetOf(data) + mark, msgAvail);
        if (mark) root->add("Record Mark: " + std::to_string(be32(data)) + " bytes", ctx.offsetOf(data), 4);
    }
    const KerberosSummary s = decodeKerberosMessage(ctx, msg, msgAvail, root);
    if (!s.tagOk) {
        pack.info = "Kerberos";
        ctx.markMalformed(msgAvail < 2 || (msg[0] & 0xe0) != 0x60 || (msg[0] & 0x1f) == 0x1f ? "Kerberos message does not start with an APPLICATION tag" : "Kerberos message length unreadable");
        return;
    }
    pack.app_type = static_cast<uint16_t>(s.appTag);
    if (s.errorCode >= 0) pack.app_code = static_cast<uint16_t>(s.errorCode);
    pack.info = s.info;
    pack.app_text = s.realm;
    pack.app_text2 = s.cname + "\n" + s.sname;   // kerberos.cname / kerberos.sname

    // a message that continues in the next segment (cut) is not an error; one whose parts contradict each other is
    if (!s.cut && !s.bodyOk) ctx.markMalformed("Kerberos message body unreadable");
    else if (s.cut && pack.ip_protocol == 17) ctx.markMalformed("Kerberos datagram shorter than its length");
}

} // namespace dissect

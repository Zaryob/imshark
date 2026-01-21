#include "kerberos.h"
#include "asn1.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *kerberosMsgTypeName(uint32_t msgType) {
    switch (msgType) {
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
        default: return "Unknown";
    }
}

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
        case 60: return "KRB_ERR_GENERIC";
        default: return "Error";
    }
}

// Extracts PrincipalName sequence: [0] name-type, [1] name-string (SEQUENCE OF GeneralString)
std::string parsePrincipalName(const uint8_t *val, size_t len) {
    ByteReader reader(val, len);
    BerTlv root;
    if (!readBerTlv(reader, root)) return {};

    std::string result;
    ByteReader seqReader(root.value, root.length);
    BerTlv item;
    while (readBerTlv(seqReader, item)) {
        if (item.isContext(1)) { // name-string (SEQUENCE OF GeneralString)
            ByteReader stringsReader(item.value, item.length);
            BerTlv innerSeq;
            if (readBerTlv(stringsReader, innerSeq)) {
                ByteReader strList(innerSeq.value, innerSeq.length);
                BerTlv s;
                while (readBerTlv(strList, s)) {
                    if (!result.empty()) result += "/";
                    result += s.asPrintable();
                }
            }
        }
    }
    return result;
}

} // namespace

StreamFrame frameKerberos(const char *data, size_t length) {
    if (length < 4) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    uint32_t pduLen = (static_cast<uint32_t>(bytes[0]) << 24) |
                      (static_cast<uint32_t>(bytes[1]) << 16) |
                      (static_cast<uint32_t>(bytes[2]) << 8) |
                      static_cast<uint32_t>(bytes[3]);

    if (pduLen > 10 * 1024 * 1024) { // 10 MB sanity check
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    size_t total = 4 + static_cast<size_t>(pduLen);
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectKerberos(Context &ctx, const char *data, size_t length) {
    if (!data || length == 0) return;

    size_t offset = 0;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    // Check if there is a 4-byte TCP framing length prefix
    if (length >= 4) {
        uint32_t tcpLen = (static_cast<uint32_t>(bytes[0]) << 24) |
                          (static_cast<uint32_t>(bytes[1]) << 16) |
                          (static_cast<uint32_t>(bytes[2]) << 8) |
                          static_cast<uint32_t>(bytes[3]);
        if (tcpLen + 4 == length && length > 4 && (bytes[4] & 0xC0) != 0) {
            // TCP framing detected
            offset = 4;
        }
    }

    ByteReader reader(bytes + offset, length - offset);
    BerTlv appTlv;
    if (!readBerTlv(reader, appTlv)) {
        return;
    }

    // Kerberos root is usually Application tag:
    // [APPLICATION 10] AS-REQ, [APPLICATION 11] AS-REP, [APPLICATION 12] TGS-REQ,
    // [APPLICATION 13] TGS-REP, [APPLICATION 14] AP-REQ, [APPLICATION 15] AP-REP,
    // [APPLICATION 30] KRB-ERROR
    uint32_t msgType = appTlv.tagNumber;
    std::string typeStr;
    if (appTlv.tagClass == asn1::Application) {
        typeStr = kerberosMsgTypeName(msgType);
    } else {
        typeStr = "Kerberos";
    }

    auto &pack = ctx.pack;
    pack.protocol = "Kerberos";
    pack.app_type = static_cast<uint16_t>(msgType);

    // Parse interior sequence
    ByteReader appReader(appTlv.value, appTlv.length);
    BerTlv bodySeq;
    int64_t pvno = 0;
    int64_t innerMsgType = msgType;
    std::string realm;
    std::string sname;
    std::string cname;
    int64_t errorCode = -1;

    if (readBerTlv(appReader, bodySeq)) {
        ByteReader seqReader(bodySeq.value, bodySeq.length);
        BerTlv element;

        while (readBerTlv(seqReader, element)) {
            if (element.tagClass == asn1::ContextSpecific) {
                ByteReader valReader(element.value, element.length);
                BerTlv inner;
                if (!readBerTlv(valReader, inner)) continue;

                switch (element.tagNumber) {
                    case 0: // pvno (INTEGER)
                        inner.asInt64(pvno);
                        break;
                    case 1: // msg-type (INTEGER)
                        if (inner.asInt64(innerMsgType)) {
                            typeStr = kerberosMsgTypeName(static_cast<uint32_t>(innerMsgType));
                        }
                        break;
                    case 3: // req-body or crealm
                        if (msgType == 30) {
                            realm = inner.asPrintable();
                        } else {
                            // req-body / ticket
                            ByteReader reqBodySeq(inner.value, inner.length);
                            BerTlv rbSeq;
                            if (readBerTlv(reqBodySeq, rbSeq)) {
                                ByteReader rbFields(rbSeq.value, rbSeq.length);
                                BerTlv f;
                                while (readBerTlv(rbFields, f)) {
                                    if (f.tagClass == asn1::ContextSpecific) {
                                        ByteReader r(f.value, f.length);
                                        BerTlv iv;
                                        if (readBerTlv(r, iv)) {
                                            if (f.tagNumber == 1) { // cname
                                                cname = parsePrincipalName(f.value, f.length);
                                            } else if (f.tagNumber == 2) { // realm
                                                realm = iv.asPrintable();
                                            } else if (f.tagNumber == 3) { // sname
                                                sname = parsePrincipalName(f.value, f.length);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    case 4: // cname in KRB-ERROR
                        if (msgType == 30) {
                            cname = parsePrincipalName(element.value, element.length);
                        }
                        break;
                    case 6: // sname in KRB-ERROR
                        if (msgType == 30) {
                            sname = parsePrincipalName(element.value, element.length);
                        }
                        break;
                    case 9: // error-code in KRB-ERROR
                        inner.asInt64(errorCode);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    std::string summary = typeStr;
    if (errorCode >= 0) {
        summary += " " + std::string(kerberosErrorCodeName(errorCode));
        pack.app_code = static_cast<uint16_t>(errorCode);
    }
    if (!cname.empty()) {
        summary += " cname=" + cname;
    }
    if (!sname.empty()) {
        summary += " sname=" + sname;
    }
    if (!realm.empty()) {
        summary += " realm=" + realm;
    }

    pack.app_text = summary;
    pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data) + offset;
        auto &root = ctx.addLayer("Kerberos (" + typeStr + ")", o, appTlv.total);
        if (pvno > 0) {
            root.add("pvno: " + std::to_string(pvno));
        }
        root.add("msg-type: " + typeStr + " (" + std::to_string(innerMsgType) + ")");
        if (errorCode >= 0) {
            root.add("error-code: " + std::string(kerberosErrorCodeName(errorCode)) + " (" + std::to_string(errorCode) + ")");
        }
        if (!cname.empty()) root.add("cname: " + cname);
        if (!sname.empty()) root.add("sname: " + sname);
        if (!realm.empty()) root.add("realm: " + realm);
    }
}

} // namespace dissect

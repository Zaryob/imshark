// LDAP (Lightweight Directory Access Protocol, RFC 4511) dissector using BER (asn1.h)
#include "ldap.h"

#include <string>
#include <vector>

#include "asn1.h"
#include "util.h"

using packet::Field;

namespace {
    using namespace dissect;

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

    std::string ldapResultCodeName(int64_t code) {
        switch (code) {
            case 0: return "success";
            case 1: return "operationsError";
            case 2: return "protocolError";
            case 3: return "timeLimitExceeded";
            case 4: return "sizeLimitExceeded";
            case 7: return "authMethodNotSupported";
            case 8: return "strongerAuthRequired";
            case 14: return "saslBindInProgress";
            case 32: return "noSuchObject";
            case 49: return "invalidCredentials";
            case 50: return "insufficientAccessRights";
            case 51: return "busy";
            case 52: return "unavailable";
            default: return "code " + std::to_string(code);
        }
    }
} // namespace

dissect::StreamFrame dissect::frameLdap(const char *data, size_t length) {
    if (length < 2) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    ByteReader r(data, length);
    BerTlv tlv;
    if (!readBerTlv(r, tlv)) {
        if (r.remaining() == 0 && length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    // Top-level must be a constructed SEQUENCE (0x30)
    if (!tlv.constructed || tlv.tagClass != asn1::Universal || tlv.tagNumber != asn1::tag::Sequence) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, tlv.total};
}

void dissect::dissectLdap(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "LDAP";

    ByteReader r(data, length);
    BerTlv topSeq;
    if (!readBerTlv(r, topSeq) || !topSeq.constructed || topSeq.tagClass != asn1::Universal || topSeq.tagNumber != asn1::tag::Sequence) {
        ctx.markMalformed("LDAP top-level SEQUENCE invalid");
        pack.info = "LDAP [Malformed]";
        return;
    }

    // Inside top sequence: MessageID (INTEGER), ProtocolOp (APPLICATION [tag]), [Controls]
    ByteReader seqReader(topSeq.value, topSeq.length);
    BerTlv msgIdTlv;
    if (!readBerTlv(seqReader, msgIdTlv) || !msgIdTlv.isUniversal(asn1::tag::Integer)) {
        ctx.markMalformed("LDAP missing MessageID");
        pack.info = "LDAP [Malformed MessageID]";
        return;
    }

    int64_t msgId = 0;
    msgIdTlv.asInt64(msgId);
    pack.tcp_pdu_start = static_cast<uint32_t>(msgId);

    BerTlv opTlv;
    if (!readBerTlv(seqReader, opTlv) || opTlv.tagClass != asn1::Application) {
        ctx.markMalformed("LDAP missing ProtocolOp");
        pack.info = "LDAP MsgID=" + std::to_string(msgId) + " [Malformed Op]";
        return;
    }

    uint32_t opTag = opTlv.tagNumber;
    pack.app_type = opTag;
    std::string opName = ldapOpName(opTag);

    std::string detail;
    std::string targetDn;

    // Parse operation specifics
    if (opTlv.constructed && opTlv.value) {
        ByteReader opReader(opTlv.value, opTlv.length);
        if (opTag == 0) { // BindRequest: version (INTEGER), name (OCTET STRING), authentication
            BerTlv verTlv, nameTlv;
            if (readBerTlv(opReader, verTlv) && readBerTlv(opReader, nameTlv)) {
                targetDn = nameTlv.asString();
                detail = "name=\"" + (targetDn.empty() ? "<anonymous>" : targetDn) + "\"";
            }
        } else if (opTag == 3) { // SearchRequest: baseObject (OCTET STRING), scope, deref, sizeLimit, timeLimit, typesOnly, Filter...
            BerTlv baseTlv;
            if (readBerTlv(opReader, baseTlv)) {
                targetDn = baseTlv.asString();
                detail = "base=\"" + targetDn + "\"";
            }
        } else if (opTag == 4) { // SearchResultEntry: objectName (OCTET STRING), attributes...
            BerTlv objTlv;
            if (readBerTlv(opReader, objTlv)) {
                targetDn = objTlv.asString();
                detail = "entry=\"" + targetDn + "\"";
            }
        } else if (opTag == 1 || opTag == 5 || opTag == 7 || opTag == 9 || opTag == 11) { // Responses: resultCode (ENUMERATED), matchedDN, diagnosticMessage
            BerTlv resTlv;
            if (readBerTlv(opReader, resTlv)) {
                int64_t resCode = 0;
                resTlv.asInt64(resCode);
                detail = "result=" + ldapResultCodeName(resCode);
            }
        }
    }

    pack.app_text = targetDn;
    pack.info = opName + " (MsgID=" + std::to_string(msgId) + (detail.empty() ? "" : ", " + detail) + ")";

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Lightweight Directory Access Protocol (" + opName + ")", o, topSeq.total);

        l.add("Message ID: " + std::to_string(msgId), o + topSeq.headerLength, msgIdTlv.total);
        Field &opf = l.add("ProtocolOp: " + opName + " (Application " + std::to_string(opTag) + ")",
                           o + topSeq.headerLength + msgIdTlv.total, opTlv.total);

        if (!targetDn.empty()) {
            opf.add("Distinguished Name / Object: " + targetDn);
        }
        if (!detail.empty()) {
            opf.add("Details: " + detail);
        }
    }
}

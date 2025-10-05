#include "protocols.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "asn1.h"
#include "util.h"

namespace dissect {
namespace {

struct OidMap {
    const char *oid;
    const char *name;
};

// Yaygın MIB-II (RFC 1213) ve SNMPv2-MIB (RFC 3418) OID adları
const OidMap kOidTable[] = {
    {"1.3.6.1.2.1.1.1.0", "sysDescr.0"},
    {"1.3.6.1.2.1.1.2.0", "sysObjectID.0"},
    {"1.3.6.1.2.1.1.3.0", "sysUpTime.0"},
    {"1.3.6.1.2.1.1.4.0", "sysContact.0"},
    {"1.3.6.1.2.1.1.5.0", "sysName.0"},
    {"1.3.6.1.2.1.1.6.0", "sysLocation.0"},
    {"1.3.6.1.2.1.1.7.0", "sysServices.0"},
    {"1.3.6.1.2.1.1.1", "sysDescr"},
    {"1.3.6.1.2.1.1.2", "sysObjectID"},
    {"1.3.6.1.2.1.1.3", "sysUpTime"},
    {"1.3.6.1.2.1.1.4", "sysContact"},
    {"1.3.6.1.2.1.1.5", "sysName"},
    {"1.3.6.1.2.1.1.6", "sysLocation"},
    {"1.3.6.1.2.1.1.7", "sysServices"},
    {"1.3.6.1.2.1.2.1.0", "ifNumber.0"},
    {"1.3.6.1.2.1.2.2.1.1", "ifIndex"},
    {"1.3.6.1.2.1.2.2.1.2", "ifDescr"},
    {"1.3.6.1.2.1.2.2.1.3", "ifType"},
    {"1.3.6.1.2.1.2.2.1.4", "ifMtu"},
    {"1.3.6.1.2.1.2.2.1.5", "ifSpeed"},
    {"1.3.6.1.2.1.2.2.1.6", "ifPhysAddress"},
    {"1.3.6.1.2.1.2.2.1.7", "ifAdminStatus"},
    {"1.3.6.1.2.1.2.2.1.8", "ifOperStatus"},
    {"1.3.6.1.2.1.2.2.1.10", "ifInOctets"},
    {"1.3.6.1.2.1.2.2.1.16", "ifOutOctets"},
    {"1.3.6.1.2.1.4.1.0", "ipForwarding.0"},
    {"1.3.6.1.2.1.4.2.0", "ipDefaultTTL.0"},
    {"1.3.6.1.2.1.4.3.0", "ipInReceives.0"},
    {"1.3.6.1.2.1.11.1.0", "snmpInPkts.0"},
    {"1.3.6.1.2.1.11.2.0", "snmpOutPkts.0"},
    {"1.3.6.1.6.3.1.1.4.1.0", "snmpTrapOID.0"},
    {"1.3.6.1.6.3.1.1.4.3.0", "snmpTrapEnterprise.0"},
    {"1.3.6.1.6.3.1.1.5.1", "coldStart"},
    {"1.3.6.1.6.3.1.1.5.2", "warmStart"},
    {"1.3.6.1.6.3.1.1.5.3", "linkDown"},
    {"1.3.6.1.6.3.1.1.5.4", "linkUp"},
    {"1.3.6.1.6.3.1.1.5.5", "authenticationFailure"},
    {"1.3.6.1.6.3.15.1.1.1.0", "usmStatsUnsupportedSecLevels.0"},
    {"1.3.6.1.6.3.15.1.1.2.0", "usmStatsNotInTimeWindows.0"},
    {"1.3.6.1.6.3.15.1.1.3.0", "usmStatsUnknownUserNames.0"},
    {"1.3.6.1.6.3.15.1.1.4.0", "usmStatsUnknownEngineIDs.0"},
    {"1.3.6.1.6.3.15.1.1.5.0", "usmStatsWrongDigests.0"},
    {"1.3.6.1.6.3.15.1.1.6.0", "usmStatsDecryptionErrors.0"}
};

std::string resolveOid(const std::string &oid) {
    if (oid.empty()) return {};
    for (const auto &entry : kOidTable) {
        if (oid == entry.oid) {
            return std::string(entry.name) + " (" + oid + ")";
        }
    }
    // Prefix match for table instances: örn. 1.3.6.1.2.1.2.2.1.2.1 -> ifDescr.1
    for (const auto &entry : kOidTable) {
        const size_t len = std::strlen(entry.oid);
        if (oid.size() > len && oid[len] == '.' && oid.rfind(entry.oid, 0) == 0) {
            return std::string(entry.name) + oid.substr(len) + " (" + oid + ")";
        }
    }
    return oid;
}

const char *errorStatusName(uint32_t status) {
    switch (status) {
        case 0: return "noError";
        case 1: return "tooBig";
        case 2: return "noSuchName";
        case 3: return "badValue";
        case 4: return "readOnly";
        case 5: return "genErr";
        case 6: return "noAccess";
        case 7: return "wrongType";
        case 8: return "wrongLength";
        case 9: return "wrongEncoding";
        case 10: return "wrongValue";
        case 11: return "noCreation";
        case 12: return "inconsistentValue";
        case 13: return "resourceUnavailable";
        case 14: return "commitFailed";
        case 15: return "undoFailed";
        case 16: return "authorizationError";
        case 17: return "notWritable";
        case 18: return "inconsistentName";
        default: return "unknownError";
    }
}

const char *genericTrapName(uint32_t trap) {
    switch (trap) {
        case 0: return "coldStart";
        case 1: return "warmStart";
        case 2: return "linkDown";
        case 3: return "linkUp";
        case 4: return "authenticationFailure";
        case 5: return "egpNeighborLoss";
        case 6: return "enterpriseSpecific";
        default: return "unknownTrap";
    }
}

const char *pduTypeName(uint32_t tagNumber) {
    switch (tagNumber) {
        case 0: return "get-request";
        case 1: return "get-next-request";
        case 2: return "response";
        case 3: return "set-request";
        case 4: return "trap";
        case 5: return "get-bulk-request";
        case 6: return "inform-request";
        case 7: return "snmpv2-trap";
        case 8: return "report";
        default: return "unknown-pdu";
    }
}

struct ParsedVarBind {
    std::string oid;
    std::string resolvedName;
    std::string valueDesc;
    size_t offset = 0;
    size_t length = 0;
};

bool parseVarBind(const BerTlv &vb, const uint8_t *base, ParsedVarBind &out) {
    if (!vb.constructed) return false;
    ByteReader r(vb.value, vb.length);
    BerTlv oidTlv;
    if (!readBerTlv(r, oidTlv) || !oidTlv.isUniversal(asn1::tag::Oid)) return false;

    out.oid = oidTlv.asOid();
    out.resolvedName = resolveOid(out.oid);
    out.offset = vb.value - base;
    out.length = vb.length;

    BerTlv valTlv;
    if (!readBerTlv(r, valTlv)) {
        out.valueDesc = "unSpecified";
        return true;
    }

    if (valTlv.tagClass == asn1::Universal) {
        switch (valTlv.tagNumber) {
            case asn1::tag::Integer: {
                int64_t num = 0;
                if (valTlv.asInt64(num)) out.valueDesc = "INTEGER: " + std::to_string(num);
                else out.valueDesc = "INTEGER: (malformed)";
                break;
            }
            case asn1::tag::OctetString: {
                bool printable = true;
                for (size_t i = 0; i < valTlv.length; ++i) {
                    if (valTlv.value[i] < 32 || valTlv.value[i] >= 127) {
                        printable = false;
                        break;
                    }
                }
                if (printable) {
                    out.valueDesc = "STRING: \"" + valTlv.asString() + "\"";
                } else {
                    out.valueDesc = "Hex-STRING: " + valTlv.asHexString();
                }
                break;
            }
            case asn1::tag::Null:
                out.valueDesc = "NULL";
                break;
            case asn1::tag::Oid:
                out.valueDesc = "OID: " + resolveOid(valTlv.asOid());
                break;
            default:
                out.valueDesc = "Tag (" + std::to_string(valTlv.tagNumber) + "): " + valTlv.asHexString();
                break;
        }
    } else if (valTlv.tagClass == asn1::Application) {
        switch (valTlv.tagNumber) {
            case 0: { // IpAddress
                if (valTlv.length == 4) {
                    out.valueDesc = "IpAddress: " + network::formatIPv4(valTlv.value);
                } else {
                    out.valueDesc = "IpAddress: " + valTlv.asHexString();
                }
                break;
            }
            case 1: { // Counter32
                uint64_t val = 0;
                valTlv.asUint64(val);
                out.valueDesc = "Counter32: " + std::to_string(val);
                break;
            }
            case 2: { // Gauge32
                uint64_t val = 0;
                valTlv.asUint64(val);
                out.valueDesc = "Gauge32: " + std::to_string(val);
                break;
            }
            case 3: { // TimeTicks
                uint64_t ticks = 0;
                valTlv.asUint64(ticks);
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%.2f", ticks / 100.0);
                out.valueDesc = "Timeticks: " + std::to_string(ticks) + " (" + buf + "s)";
                break;
            }
            case 4: // Opaque
                out.valueDesc = "Opaque: " + std::to_string(valTlv.length) + " bytes";
                break;
            case 6: { // Counter64
                uint64_t val = 0;
                valTlv.asUint64(val);
                out.valueDesc = "Counter64: " + std::to_string(val);
                break;
            }
            default:
                out.valueDesc = "Application [" + std::to_string(valTlv.tagNumber) + "]: " + valTlv.asHexString();
                break;
        }
    } else if (valTlv.tagClass == asn1::ContextSpecific) {
        switch (valTlv.tagNumber) {
            case 0: out.valueDesc = "noSuchObject"; break;
            case 1: out.valueDesc = "noSuchInstance"; break;
            case 2: out.valueDesc = "endOfMibView"; break;
            default: out.valueDesc = "Context [" + std::to_string(valTlv.tagNumber) + "]"; break;
        }
    }
    return true;
}

} // namespace

void dissectSnmp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "SNMP";
    if (length < 2) {
        ctx.pack.info = "SNMP (truncated)";
        return;
    }

    const auto *base = reinterpret_cast<const uint8_t *>(data);
    const size_t baseOffset = ctx.offsetOf(data);

    BerTlv msg;
    if (!readBerTlv(base, length, msg) || msg.rawTag != 0x30) {
        ctx.pack.info = "SNMP (malformed message: not a SEQUENCE)";
        if (ctx.wantFields()) {
            packet::Field &l = ctx.addLayer("Simple Network Management Protocol", baseOffset, length);
            l.add("[Malformed Packet: SNMP message is not a valid BER SEQUENCE]", baseOffset, length);
        }
        return;
    }

    ByteReader msgReader(msg.value, msg.length);
    BerTlv versionTlv;
    if (!readBerTlv(msgReader, versionTlv) || !versionTlv.isUniversal(asn1::tag::Integer)) {
        ctx.pack.info = "SNMP (malformed: missing version)";
        return;
    }

    int64_t verNum = 0;
    versionTlv.asInt64(verNum);
    const uint32_t version = static_cast<uint32_t>(verNum);
    ctx.pack.app_flags = static_cast<uint16_t>(version);

    std::string verStr;
    if (version == 0) verStr = "v1 (0)";
    else if (version == 1) verStr = "v2c (1)";
    else if (version == 3) verStr = "v3 (3)";
    else verStr = "unknown (" + std::to_string(version) + ")";

    std::string community;
    BerTlv pduTlv;

    // SNMPv3 alanları
    uint32_t msgId = 0, msgMaxSize = 0, msgSecModel = 0;
    uint8_t msgFlags = 0;
    std::string secEngineId, secUserName, secAuthParams, secPrivParams;
    uint32_t secEngineBoots = 0, secEngineTime = 0;
    bool isEncrypted = false;
    std::string ctxEngineId, ctxName;

    if (version == 0 || version == 1) {
        BerTlv commTlv;
        if (!readBerTlv(msgReader, commTlv) || !commTlv.isUniversal(asn1::tag::OctetString)) {
            ctx.pack.info = "SNMP " + verStr + " (malformed: missing community)";
            return;
        }
        community = commTlv.asString();
        ctx.pack.app_text = community;

        if (!readBerTlv(msgReader, pduTlv)) {
            ctx.pack.info = "SNMP " + verStr + " (malformed: missing PDU)";
            return;
        }
    } else if (version == 3) {
        // SNMPv3: msgGlobalData
        BerTlv globalDataTlv;
        if (readBerTlv(msgReader, globalDataTlv) && globalDataTlv.constructed) {
            ByteReader gdReader(globalDataTlv.value, globalDataTlv.length);
            BerTlv idTlv, maxTlv, flagsTlv, modelTlv;
            if (readBerTlv(gdReader, idTlv)) { int64_t v = 0; idTlv.asInt64(v); msgId = static_cast<uint32_t>(v); }
            if (readBerTlv(gdReader, maxTlv)) { int64_t v = 0; maxTlv.asInt64(v); msgMaxSize = static_cast<uint32_t>(v); }
            if (readBerTlv(gdReader, flagsTlv) && flagsTlv.length > 0) msgFlags = flagsTlv.value[0];
            if (readBerTlv(gdReader, modelTlv)) { int64_t v = 0; modelTlv.asInt64(v); msgSecModel = static_cast<uint32_t>(v); }
        }

        // msgSecurityParameters (OCTET STRING containing USM SEQUENCE)
        BerTlv secParamStringTlv;
        if (readBerTlv(msgReader, secParamStringTlv) && secParamStringTlv.isUniversal(asn1::tag::OctetString)) {
            BerTlv usmTlv;
            if (readBerTlv(secParamStringTlv.value, secParamStringTlv.length, usmTlv) && usmTlv.constructed) {
                ByteReader usmR(usmTlv.value, usmTlv.length);
                BerTlv eId, boots, time, user, authP, privP;
                if (readBerTlv(usmR, eId)) secEngineId = eId.asHexString();
                if (readBerTlv(usmR, boots)) { int64_t v = 0; boots.asInt64(v); secEngineBoots = static_cast<uint32_t>(v); }
                if (readBerTlv(usmR, time)) { int64_t v = 0; time.asInt64(v); secEngineTime = static_cast<uint32_t>(v); }
                if (readBerTlv(usmR, user)) {
                    secUserName = user.asString();
                    ctx.pack.app_text = secUserName;
                }
                if (readBerTlv(usmR, authP)) secAuthParams = authP.asHexString();
                if (readBerTlv(usmR, privP)) secPrivParams = privP.asHexString();
            }
        }

        // msgData / ScopedPduData
        BerTlv scopedDataTlv;
        if (readBerTlv(msgReader, scopedDataTlv)) {
            if (scopedDataTlv.isUniversal(asn1::tag::OctetString) || (msgFlags & 0x02) != 0) {
                isEncrypted = true;
            } else if (scopedDataTlv.constructed) {
                ByteReader scReader(scopedDataTlv.value, scopedDataTlv.length);
                BerTlv ceId, cName;
                if (readBerTlv(scReader, ceId)) ctxEngineId = ceId.asHexString();
                if (readBerTlv(scReader, cName)) ctxName = cName.asString();
                readBerTlv(scReader, pduTlv);
            }
        }
    } else {
        ctx.pack.info = "SNMP " + verStr + " (unsupported version)";
        return;
    }

    if (isEncrypted) {
        ctx.pack.info = "SNMPv3 encrypted PDU (user: " + (secUserName.empty() ? "<unknown>" : secUserName) + ")";
        if (ctx.wantFields()) {
            packet::Field &l = ctx.addLayer("Simple Network Management Protocol", baseOffset, msg.total);
            l.add("msgVersion: " + verStr, baseOffset + (versionTlv.value - base), versionTlv.length);
            l.add("msgID: " + std::to_string(msgId), baseOffset, 4);
            l.add("msgMaxSize: " + std::to_string(msgMaxSize), baseOffset, 4);
            l.add("msgFlags: " + hexString(msgFlags, 2) + " [Reportable=" + std::to_string((msgFlags & 0x04) != 0) +
                  ", Encrypted=" + std::to_string((msgFlags & 0x02) != 0) +
                  ", Authenticated=" + std::to_string((msgFlags & 0x01) != 0) + "]", baseOffset, 1);
            l.add("msgSecurityModel: USM (" + std::to_string(msgSecModel) + ")", baseOffset, 2);
            packet::Field &secTree = l.add("msgSecurityParameters (USM)", baseOffset, 0);
            if (!secUserName.empty()) secTree.add("msgUserName: " + secUserName, baseOffset, 0);
            if (!secEngineId.empty()) secTree.add("msgAuthoritativeEngineID: " + secEngineId, baseOffset, 0);
            l.add("[ScopedPDU encrypted - not decrypted]", baseOffset, length);
        }
        return;
    }

    if (pduTlv.tagClass != asn1::ContextSpecific) {
        ctx.pack.info = "SNMP " + verStr + " (malformed PDU)";
        return;
    }

    const uint32_t pduType = pduTlv.tagNumber;
    ctx.pack.app_type = static_cast<uint16_t>(pduType);
    const std::string pduName = pduTypeName(pduType);

    ByteReader pduReader(pduTlv.value, pduTlv.length);
    uint32_t requestId = 0;
    uint32_t errorStatus = 0;
    uint32_t errorIndex = 0;
    uint32_t nonRepeaters = 0;
    uint32_t maxRepetitions = 0;
    std::string trapEnterprise;
    std::string trapAgentAddr;
    uint32_t genericTrap = 0;
    uint32_t specificTrap = 0;
    uint32_t trapTimestamp = 0;

    BerTlv vbListTlv;

    if (pduType == 4) { // Trap-v1 PDU
        BerTlv ent, addr, gen, spec, time;
        if (readBerTlv(pduReader, ent)) trapEnterprise = resolveOid(ent.asOid());
        if (readBerTlv(pduReader, addr) && addr.length == 4) trapAgentAddr = network::formatIPv4(addr.value);
        if (readBerTlv(pduReader, gen)) { int64_t v = 0; gen.asInt64(v); genericTrap = static_cast<uint32_t>(v); }
        if (readBerTlv(pduReader, spec)) { int64_t v = 0; spec.asInt64(v); specificTrap = static_cast<uint32_t>(v); }
        if (readBerTlv(pduReader, time)) { uint64_t v = 0; time.asUint64(v); trapTimestamp = static_cast<uint32_t>(v); }
        readBerTlv(pduReader, vbListTlv);
    } else {
        BerTlv reqIdTlv, errStatTlv, errIdxTlv;
        if (readBerTlv(pduReader, reqIdTlv)) {
            int64_t v = 0;
            reqIdTlv.asInt64(v);
            requestId = static_cast<uint32_t>(v);
            ctx.pack.tcp_pdu_start = requestId;
        }

        if (pduType == 5) { // GetBulk
            if (readBerTlv(pduReader, errStatTlv)) { int64_t v = 0; errStatTlv.asInt64(v); nonRepeaters = static_cast<uint32_t>(v); }
            if (readBerTlv(pduReader, errIdxTlv)) { int64_t v = 0; errIdxTlv.asInt64(v); maxRepetitions = static_cast<uint32_t>(v); }
        } else {
            if (readBerTlv(pduReader, errStatTlv)) { int64_t v = 0; errStatTlv.asInt64(v); errorStatus = static_cast<uint32_t>(v); }
            if (readBerTlv(pduReader, errIdxTlv)) { int64_t v = 0; errIdxTlv.asInt64(v); errorIndex = static_cast<uint32_t>(v); }
            ctx.pack.app_code = static_cast<uint16_t>(errorStatus);
        }
        readBerTlv(pduReader, vbListTlv);
    }

    std::vector<ParsedVarBind> varbinds;
    if (vbListTlv.constructed) {
        eachChild(vbListTlv, [&](const BerTlv &vb) {
            ParsedVarBind pv;
            if (parseVarBind(vb, base, pv)) {
                varbinds.push_back(std::move(pv));
            }
        });
    }

    if (!varbinds.empty()) {
        ctx.pack.app_text2 = varbinds[0].oid;
    }

    // Info metni oluşturma
    if (pduType == 4) {
        ctx.pack.info = "trap " + std::string(genericTrapName(genericTrap)) + " enterprise=" + trapEnterprise;
    } else if (errorStatus != 0) {
        ctx.pack.info = pduName + " error: " + errorStatusName(errorStatus) + " at index " + std::to_string(errorIndex);
    } else if (!varbinds.empty()) {
        ctx.pack.info = pduName + " " + varbinds[0].resolvedName;
    } else {
        ctx.pack.info = pduName + " request-id=" + std::to_string(requestId);
    }

    // Paket detay ağacı
    if (!ctx.wantFields()) return;

    packet::Field &l = ctx.addLayer("Simple Network Management Protocol", baseOffset, msg.total);
    l.add("version: " + verStr, baseOffset + (versionTlv.value - base), versionTlv.length);

    if (version == 0 || version == 1) {
        l.add("community: " + community, baseOffset, community.size());
    } else if (version == 3) {
        packet::Field &hTree = l.add("msgGlobalData", baseOffset, 0);
        hTree.add("msgID: " + std::to_string(msgId), baseOffset, 4);
        hTree.add("msgMaxSize: " + std::to_string(msgMaxSize), baseOffset, 4);
        hTree.add("msgFlags: " + hexString(msgFlags, 2), baseOffset, 1);
        hTree.add("msgSecurityModel: USM (" + std::to_string(msgSecModel) + ")", baseOffset, 2);

        packet::Field &sTree = l.add("msgSecurityParameters (USM)", baseOffset, 0);
        if (!secEngineId.empty()) sTree.add("msgAuthoritativeEngineID: " + secEngineId, baseOffset, 0);
        sTree.add("msgAuthoritativeEngineBoots: " + std::to_string(secEngineBoots), baseOffset, 0);
        sTree.add("msgAuthoritativeEngineTime: " + std::to_string(secEngineTime), baseOffset, 0);
        if (!secUserName.empty()) sTree.add("msgUserName: " + secUserName, baseOffset, 0);
        if (!secAuthParams.empty()) sTree.add("msgAuthenticationParameters: " + secAuthParams, baseOffset, 0);
        if (!secPrivParams.empty()) sTree.add("msgPrivacyParameters: " + secPrivParams, baseOffset, 0);

        packet::Field &cTree = l.add("ScopedPDU", baseOffset, 0);
        if (!ctxEngineId.empty()) cTree.add("contextEngineID: " + ctxEngineId, baseOffset, 0);
        if (!ctxName.empty()) cTree.add("contextName: " + ctxName, baseOffset, 0);
    }

    const size_t pduOffset = baseOffset + (pduTlv.value - base);
    packet::Field &pTree = l.add("data: " + pduName + " (" + std::to_string(pduType) + ")", pduOffset, pduTlv.length);

    if (pduType == 4) {
        pTree.add("enterprise: " + trapEnterprise, pduOffset, 0);
        if (!trapAgentAddr.empty()) pTree.add("agent-addr: " + trapAgentAddr, pduOffset, 4);
        pTree.add("generic-trap: " + std::string(genericTrapName(genericTrap)) + " (" + std::to_string(genericTrap) + ")", pduOffset, 0);
        pTree.add("specific-trap: " + std::to_string(specificTrap), pduOffset, 0);
        pTree.add("time-stamp: " + std::to_string(trapTimestamp), pduOffset, 0);
    } else {
        pTree.add("request-id: " + std::to_string(requestId), pduOffset, 4);
        if (pduType == 5) {
            pTree.add("non-repeaters: " + std::to_string(nonRepeaters), pduOffset, 0);
            pTree.add("max-repetitions: " + std::to_string(maxRepetitions), pduOffset, 0);
        } else {
            pTree.add("error-status: " + std::string(errorStatusName(errorStatus)) + " (" + std::to_string(errorStatus) + ")", pduOffset, 0);
            pTree.add("error-index: " + std::to_string(errorIndex), pduOffset, 0);
        }
    }

    if (!varbinds.empty()) {
        packet::Field &vbTree = pTree.add("variable-bindings: " + std::to_string(varbinds.size()) + " items", pduOffset, 0);
        for (size_t i = 0; i < varbinds.size(); ++i) {
            const auto &vb = varbinds[i];
            packet::Field &item = vbTree.add(vb.resolvedName + ": " + vb.valueDesc, baseOffset + vb.offset, vb.length);
            item.add("Object Name: " + vb.resolvedName, baseOffset + vb.offset, 0);
            item.add("Value: " + vb.valueDesc, baseOffset + vb.offset, 0);
        }
    }
}

} // namespace dissect

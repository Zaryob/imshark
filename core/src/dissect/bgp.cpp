#include "protocols.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "reader.h"
#include "util.h"

namespace dissect {

StreamFrame frameBgp(const char *data, size_t length) {
    if (length < 19) {
        // İlk baytların 0xff olup olmadığını kontrol et
        for (size_t i = 0; i < length && i < 16; ++i) {
            if (static_cast<uint8_t>(data[i]) != 0xff) return {StreamFrame::Kind::Reject};
        }
        return {StreamFrame::Kind::NeedMore, 19};
    }
    for (size_t i = 0; i < 16; ++i) {
        if (static_cast<uint8_t>(data[i]) != 0xff) return {StreamFrame::Kind::Reject};
    }
    const uint16_t msgLen = be16(data + 16);
    if (msgLen < 19 || msgLen > 4096) return {StreamFrame::Kind::Reject};

    if (length < msgLen) return {StreamFrame::Kind::NeedMore, msgLen};
    return {StreamFrame::Kind::Complete, msgLen};
}

namespace {

const char *bgpTypeName(uint8_t type) {
    switch (type) {
        case 1: return "OPEN";
        case 2: return "UPDATE";
        case 3: return "NOTIFICATION";
        case 4: return "KEEPALIVE";
        case 5: return "ROUTE-REFRESH";
        default: return "UNKNOWN";
    }
}

const char *originName(uint8_t origin) {
    switch (origin) {
        case 0: return "IGP (0)";
        case 1: return "EGP (1)";
        case 2: return "INCOMPLETE (2)";
        default: return "Unknown";
    }
}

const char *asSegmentTypeName(uint8_t type) {
    switch (type) {
        case 1: return "AS_SET";
        case 2: return "AS_SEQUENCE";
        case 3: return "AS_CONFED_SEQUENCE";
        case 4: return "AS_CONFED_SET";
        default: return "Unknown";
    }
}

const char *notificationCodeName(uint8_t code) {
    switch (code) {
        case 1: return "Message Header Error";
        case 2: return "OPEN Message Error";
        case 3: return "UPDATE Message Error";
        case 4: return "Hold Timer Expired";
        case 5: return "Finite State Machine Error";
        case 6: return "Cease";
        case 7: return "ROUTE-REFRESH Message Error";
        default: return "Unknown Error";
    }
}

const char *notificationSubcodeName(uint8_t code, uint8_t subcode) {
    switch (code) {
        case 1: // Message Header Error
            switch (subcode) {
                case 1: return "Connection Not Synchronized";
                case 2: return "Bad Message Length";
                case 3: return "Bad Message Type";
                default: return "Unspecific";
            }
        case 2: // OPEN Message Error
            switch (subcode) {
                case 1: return "Unsupported Version Number";
                case 2: return "Bad Peer AS";
                case 3: return "Bad BGP Identifier";
                case 4: return "Unsupported Optional Parameter";
                case 5: return "Deprecated";
                case 6: return "Unacceptable Hold Time";
                case 7: return "Unsupported Capability";
                default: return "Unspecific";
            }
        case 3: // UPDATE Message Error
            switch (subcode) {
                case 1: return "Malformed Attribute List";
                case 2: return "Unrecognized Well-known Attribute";
                case 3: return "Missing Well-known Attribute";
                case 4: return "Attribute Flags Error";
                case 5: return "Attribute Length Error";
                case 6: return "Invalid ORIGIN Attribute";
                case 7: return "Deprecated";
                case 8: return "Invalid NEXT_HOP Attribute";
                case 9: return "Optional Attribute Error";
                case 10: return "Invalid Network Field";
                case 11: return "Malformed AS_PATH";
                default: return "Unspecific";
            }
        case 5: // FSM Error
            switch (subcode) {
                case 1: return "Unspecified Error";
                case 2: return "Receive Unexpected Message in OpenSent";
                case 3: return "Receive Unexpected Message in OpenConfirm";
                case 4: return "Receive Unexpected Message in Established";
                default: return "Unspecific";
            }
        case 6: // Cease
            switch (subcode) {
                case 1: return "Maximum Number of Prefixes Reached";
                case 2: return "Administrative Shutdown";
                case 3: return "Peer De-configured";
                case 4: return "Administrative Reset";
                case 5: return "Connection Rejected";
                case 6: return "Other Configuration Change";
                case 7: return "Connection Collision Resolution";
                case 8: return "Out of Resources";
                default: return "Unspecific";
            }
        default:
            return "Unspecific";
    }
}

// BGP IPv4 prefix okuyucu (prefix_len bit + (prefix_len+7)/8 bayt)
std::string readPrefix(ByteReader &r) {
    if (!r.ok() || r.remaining() < 1) return {};
    const uint8_t bitLen = r.u8();
    if (bitLen > 32) {
        r.fail();
        return {};
    }
    const size_t byteCount = (bitLen + 7) / 8;
    if (r.remaining() < byteCount) {
        r.fail();
        return {};
    }
    uint8_t ip[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < byteCount; ++i) {
        ip[i] = r.u8();
    }
    return network::formatIPv4(ip) + "/" + std::to_string(bitLen);
}

} // namespace

void dissectBgp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "BGP";
    if (length < 19) {
        ctx.pack.info = "BGP (truncated: length < 19)";
        return;
    }

    const size_t baseOffset = ctx.offsetOf(data);
    ByteReader r(data, length);

    // Marker (16 bayt 0xff)
    auto marker = r.readBytes(16);
    bool markerValid = true;
    for (uint8_t b : marker) {
        if (b != 0xff) { markerValid = false; break; }
    }

    const uint16_t msgLen = r.u16_be();
    const uint8_t msgType = r.u8();
    ctx.pack.app_type = msgType;

    const std::string typeName = bgpTypeName(msgType);
    const size_t bodyLen = (msgLen >= 19 && msgLen <= length) ? msgLen - 19 : (length >= 19 ? length - 19 : 0);
    ByteReader body = r.sub(bodyLen);

    packet::Field *bgpLayer = nullptr;
    if (ctx.wantFields()) {
        bgpLayer = &ctx.addLayer("Border Gateway Protocol - " + typeName, baseOffset, msgLen <= length ? msgLen : length);
        bgpLayer->add(std::string("Marker: ") + (markerValid ? "16 bytes (valid)" : "16 bytes (corrupted)"), baseOffset, 16);
        bgpLayer->add("Length: " + std::to_string(msgLen), baseOffset + 16, 2);
        bgpLayer->add("Type: " + typeName + " (" + std::to_string(msgType) + ")", baseOffset + 18, 1);
    }

    if (msgType == 1) { // OPEN
        if (body.remaining() < 10) {
            ctx.pack.info = "OPEN Message (truncated)";
            return;
        }
        const uint8_t ver = body.u8();
        const uint16_t myAs16 = body.u16_be();
        const uint16_t holdTime = body.u16_be();
        auto bgpIdBytes = body.readBytes(4);
        const std::string bgpId = network::formatIPv4(bgpIdBytes.data());
        const uint8_t optLen = body.u8();

        uint32_t myAs = myAs16;
        ctx.pack.app_code = myAs16;
        ctx.pack.tcp_pdu_start = myAs;
        ctx.pack.app_text = bgpId;

        ctx.pack.info = "OPEN Message, AS " + std::to_string(myAs) + ", hold time " + std::to_string(holdTime) + ", ID " + bgpId;

        packet::Field *openTree = nullptr;
        if (ctx.wantFields() && bgpLayer) {
            openTree = &bgpLayer->add("OPEN Message", baseOffset + 19, bodyLen);
            openTree->add("Version: " + std::to_string(ver), baseOffset + 19, 1);
            openTree->add("My AS: " + std::to_string(myAs16), baseOffset + 20, 2);
            openTree->add("Hold Time: " + std::to_string(holdTime), baseOffset + 22, 2);
            openTree->add("BGP Identifier: " + bgpId, baseOffset + 24, 4);
            openTree->add("Optional Parameters Length: " + std::to_string(optLen), baseOffset + 28, 1);
        }

        // Optional parameters / Capabilities
        const size_t optAvail = std::min<size_t>(optLen, body.remaining());   // ranges below never leave the message
        ByteReader optReader = body.sub(optAvail);
        if (openTree && optLen > 0) {
            packet::Field &optTree = openTree->add("Optional Parameters (" + std::to_string(optLen) + " bytes)", baseOffset + 29, optAvail);
            while (optReader.remaining() >= 2) {
                const size_t paramOff = baseOffset + 29 + optReader.offset();
                const uint8_t pType = optReader.u8();
                const uint8_t pLen = optReader.u8();
                const size_t pAvail = std::min<size_t>(pLen, optReader.remaining());
                ByteReader pVal = optReader.sub(pAvail);
                if (pType == 2) { // Capabilities
                    packet::Field &capParam = optTree.add("Capabilities (" + std::to_string(pLen) + " bytes)", paramOff, 2 + pAvail);
                    while (pVal.remaining() >= 2) {
                        const size_t cOff = paramOff + 2 + pVal.offset();
                        const uint8_t cCode = pVal.u8();
                        const uint8_t cLen = pVal.u8();
                        const size_t cAvail = std::min<size_t>(cLen, pVal.remaining());
                        ByteReader cVal = pVal.sub(cAvail);
                        if (cCode == 65 && cLen == 4) { // 4-octet AS
                            const uint32_t as4 = cVal.u32_be();
                            ctx.pack.app_flags |= 0x0001; // 4-octet AS capability görüldü!
                            ctx.pack.tcp_pdu_start = as4;
                            capParam.add("Support for 4-octet AS number: " + std::to_string(as4), cOff, 2 + cAvail);
                        } else if (cCode == 1 && cLen == 4) { // Multiprotocol
                            const uint16_t afi = cVal.u16_be();
                            cVal.skip(1); // res
                            const uint8_t safi = cVal.u8();
                            capParam.add("Multiprotocol Extensions: AFI=" + std::to_string(afi) + ", SAFI=" + std::to_string(safi), cOff, 2 + cAvail);
                        } else if (cCode == 2) {
                            capParam.add("Route Refresh Capability", cOff, 2 + cAvail);
                        } else if (cCode == 64) {
                            capParam.add("Graceful Restart Capability", cOff, 2 + cAvail);
                        } else if (cCode == 69) {
                            capParam.add("ADD-PATH Capability", cOff, 2 + cAvail);
                        } else {
                            capParam.add("Capability: " + std::to_string(cCode) + " (" + std::to_string(cLen) + " bytes)", cOff, 2 + cAvail);
                        }
                    }
                } else {
                    optTree.add("Parameter: type " + std::to_string(pType) + " (" + std::to_string(pLen) + " bytes)", paramOff, 2 + pAvail);
                }
            }
        }
    } else if (msgType == 2) { // UPDATE
        if (body.remaining() < 4) {
            ctx.pack.info = "UPDATE Message (truncated)";
            return;
        }
        const uint16_t withdrawnLen = body.u16_be();
        ByteReader withdrawnReader = body.sub(withdrawnLen);

        std::vector<std::string> withdrawnRoutes;
        while (withdrawnReader.ok() && withdrawnReader.remaining() > 0) {
            std::string pfx = readPrefix(withdrawnReader);
            if (!pfx.empty()) withdrawnRoutes.push_back(std::move(pfx));
        }

        const uint16_t attrLen = body.u16_be();
        ByteReader attrReader = body.sub(attrLen);

        std::vector<std::string> attrNames;
        std::string originStr, nextHopStr;
        std::vector<uint32_t> asPath;
        bool as4Guessed = false;

        packet::Field *updateTree = nullptr;
        if (ctx.wantFields() && bgpLayer) {
            updateTree = &bgpLayer->add("UPDATE Message", baseOffset + 19, bodyLen);
            if (withdrawnLen > 0 && withdrawnReader.ok()) {   // a length beyond the message has no bytes to show
                packet::Field &wTree = updateTree->add("Withdrawn Routes (" + std::to_string(withdrawnLen) + " bytes): " +
                                                       std::to_string(withdrawnRoutes.size()) + " routes", baseOffset + 21, withdrawnLen);
                for (const auto &w : withdrawnRoutes) wTree.add("Route: " + w, baseOffset + 21, 0);
            }
        }

        packet::Field *attrsTree = nullptr;
        if (updateTree && attrLen > 0 && attrReader.ok()) {
            attrsTree = &updateTree->add("Path Attributes (" + std::to_string(attrLen) + " bytes)", baseOffset + 23 + withdrawnLen, attrLen);
        }

        // Path attributes döngüsü
        while (attrReader.ok() && attrReader.remaining() >= 2) {
            const size_t aOff = baseOffset + 23 + withdrawnLen + attrReader.offset();
            const uint8_t flags = attrReader.u8();
            const uint8_t code = attrReader.u8();
            size_t valLen = 0;
            if (flags & 0x10) { // Extended length
                if (attrReader.remaining() < 2) break;
                valLen = attrReader.u16_be();
            } else {
                if (attrReader.remaining() < 1) break;
                valLen = attrReader.u8();
            }
            ByteReader valReader = attrReader.sub(valLen);

            switch (code) {
                case 1: { // ORIGIN
                    attrNames.push_back("ORIGIN");
                    if (valReader.remaining() >= 1) {
                        originStr = originName(valReader.u8());
                        if (attrsTree) attrsTree->add("ORIGIN: " + originStr, aOff, valLen + 3);
                    }
                    break;
                }
                case 2: // AS_PATH
                case 17: { // AS4_PATH
                    const bool isAs4Explicit = (code == 17);
                    attrNames.push_back(isAs4Explicit ? "AS4_PATH" : "AS_PATH");
                    // AS boyutu seçimi: OPEN capability (app_flags bit 0), veya tahmin
                    bool is4Byte = isAs4Explicit || (ctx.pack.app_flags & 0x0001);
                    if (!is4Byte && valReader.remaining() >= 2) {
                        const uint8_t segLen = valReader.data()[valReader.offset() + 1];
                        if (segLen > 0 && (valLen - 2) == static_cast<size_t>(segLen * 4)) {
                            is4Byte = true;
                            as4Guessed = true;
                            ctx.pack.app_flags |= 0x0002; // [AS size guessed]
                        }
                    }
                    std::string asPathStr;
                    uint8_t firstSegType = 0;
                    while (valReader.ok() && valReader.remaining() >= 2) {
                        const uint8_t segType = valReader.u8();
                        if (firstSegType == 0) firstSegType = segType;
                        const uint8_t segCount = valReader.u8();
                        for (uint8_t s = 0; s < segCount && valReader.remaining() >= (is4Byte ? 4u : 2u); ++s) {
                            const uint32_t asNum = is4Byte ? valReader.u32_be() : valReader.u16_be();
                            asPath.push_back(asNum);
                            if (!asPathStr.empty()) asPathStr += " ";
                            asPathStr += std::to_string(asNum);
                        }
                    }
                    if (!asPath.empty()) {
                        ctx.pack.tcp_pdu_start = asPath[0]; // first AS for bgp.as filter
                    }
                    if (attrsTree) {
                        std::string label = (isAs4Explicit ? "AS4_PATH: " : "AS_PATH: ") + asPathStr;
                        if (as4Guessed) label += " [AS size guessed]";
                        packet::Field &asf = attrsTree->add(label, aOff, valLen + 3);
                        if (firstSegType != 0) {
                            asf.add(std::string("Segment type: ") + asSegmentTypeName(firstSegType), aOff, 1);
                        }
                    }
                    break;
                }
                case 3: { // NEXT_HOP
                    attrNames.push_back("NEXT_HOP");
                    if (valReader.remaining() >= 4) {
                        auto ip = valReader.readBytes(4);
                        nextHopStr = network::formatIPv4(ip.data());
                        if (attrsTree) attrsTree->add("NEXT_HOP: " + nextHopStr, aOff, valLen + 3);
                    }
                    break;
                }
                case 4: { // MED
                    attrNames.push_back("MED");
                    if (valReader.remaining() >= 4) {
                        uint32_t med = valReader.u32_be();
                        if (attrsTree) attrsTree->add("MULTI_EXIT_DISC: " + std::to_string(med), aOff, valLen + 3);
                    }
                    break;
                }
                case 5: { // LOCAL_PREF
                    attrNames.push_back("LOCAL_PREF");
                    if (valReader.remaining() >= 4) {
                        uint32_t lp = valReader.u32_be();
                        if (attrsTree) attrsTree->add("LOCAL_PREF: " + std::to_string(lp), aOff, valLen + 3);
                    }
                    break;
                }
                case 6: { // ATOMIC_AGGREGATE
                    attrNames.push_back("ATOMIC_AGGREGATE");
                    if (attrsTree) attrsTree->add("ATOMIC_AGGREGATE", aOff, valLen + 3);
                    break;
                }
                case 7: { // AGGREGATOR
                    attrNames.push_back("AGGREGATOR");
                    if (attrsTree) attrsTree->add("AGGREGATOR", aOff, valLen + 3);
                    break;
                }
                case 8: { // COMMUNITIES
                    attrNames.push_back("COMMUNITIES");
                    std::string commStr;
                    while (valReader.remaining() >= 4) {
                        uint16_t as = valReader.u16_be();
                        uint16_t val = valReader.u16_be();
                        if (!commStr.empty()) commStr += " ";
                        commStr += std::to_string(as) + ":" + std::to_string(val);
                    }
                    if (attrsTree) attrsTree->add("COMMUNITIES: " + commStr, aOff, valLen + 3);
                    break;
                }
                case 14: { // MP_REACH_NLRI
                    attrNames.push_back("MP_REACH_NLRI");
                    if (attrsTree) attrsTree->add("MP_REACH_NLRI (" + std::to_string(valLen) + " bytes)", aOff, valLen + 3);
                    break;
                }
                case 15: { // MP_UNREACH_NLRI
                    attrNames.push_back("MP_UNREACH_NLRI");
                    if (attrsTree) attrsTree->add("MP_UNREACH_NLRI (" + std::to_string(valLen) + " bytes)", aOff, valLen + 3);
                    break;
                }
                default: {
                    if (attrsTree) attrsTree->add("Attribute type " + std::to_string(code) + " (" + std::to_string(valLen) + " bytes)", aOff, valLen + 3);
                    break;
                }
            }
        }

        // NLRI (kalan baytlar)
        std::vector<std::string> nlriRoutes;
        while (body.ok() && body.remaining() > 0) {
            std::string pfx = readPrefix(body);
            if (!pfx.empty()) nlriRoutes.push_back(std::move(pfx));
        }

        if (!nlriRoutes.empty()) {
            ctx.pack.app_text = nlriRoutes[0];
        } else if (!withdrawnRoutes.empty()) {
            ctx.pack.app_text = withdrawnRoutes[0];
        }

        if (updateTree && !nlriRoutes.empty()) {
            const size_t nlriOff = baseOffset + 23 + withdrawnLen + attrLen;
            packet::Field &nTree = updateTree->add("Network Layer Reachability Information: " +
                                                   std::to_string(nlriRoutes.size()) + " routes", nlriOff, bodyLen - (23 + withdrawnLen + attrLen - 19));
            for (const auto &n : nlriRoutes) nTree.add("NLRI: " + n, nlriOff, 0);
        }

        std::string infoStr = "UPDATE Message";
        if (withdrawnRoutes.size() > 0) infoStr += ", withdrawn " + std::to_string(withdrawnRoutes.size());
        if (nlriRoutes.size() > 0) infoStr += ", NLRI " + std::to_string(nlriRoutes.size());
        if (!attrNames.empty()) {
            infoStr += ", attrs";
            for (const auto &an : attrNames) infoStr += " " + an;
        }
        ctx.pack.info = infoStr;
    } else if (msgType == 3) { // NOTIFICATION
        if (body.remaining() < 2) {
            ctx.pack.info = "NOTIFICATION Message (truncated)";
            return;
        }
        const uint8_t errCode = body.u8();
        const uint8_t errSub = body.u8();
        ctx.pack.app_code = errCode;

        const std::string cName = notificationCodeName(errCode);
        const std::string sName = notificationSubcodeName(errCode, errSub);
        ctx.pack.info = "NOTIFICATION Message (" + cName + " - " + sName + ")";

        if (ctx.wantFields() && bgpLayer) {
            packet::Field &notifTree = bgpLayer->add("NOTIFICATION Message", baseOffset + 19, bodyLen);
            notifTree.add("Error Code: " + cName + " (" + std::to_string(errCode) + ")", baseOffset + 19, 1);
            notifTree.add("Error Subcode: " + sName + " (" + std::to_string(errSub) + ")", baseOffset + 20, 1);
            if (body.remaining() > 0) {
                notifTree.add("Data (" + std::to_string(body.remaining()) + " bytes)", baseOffset + 21, body.remaining());
            }
        }
    } else if (msgType == 4) { // KEEPALIVE
        ctx.pack.info = "KEEPALIVE Message";
    } else if (msgType == 5) { // ROUTE-REFRESH
        if (body.remaining() < 4) {
            ctx.pack.info = "ROUTE-REFRESH Message (truncated)";
            return;
        }
        const uint16_t afi = body.u16_be();
        body.skip(1); // res
        const uint8_t safi = body.u8();
        ctx.pack.info = "ROUTE-REFRESH Message (AFI=" + std::to_string(afi) + ", SAFI=" + std::to_string(safi) + ")";
        if (ctx.wantFields() && bgpLayer) {
            packet::Field &rrTree = bgpLayer->add("ROUTE-REFRESH Message", baseOffset + 19, bodyLen);
            rrTree.add("AFI: " + std::to_string(afi), baseOffset + 19, 2);
            rrTree.add("SAFI: " + std::to_string(safi), baseOffset + 22, 1);
        }
    } else {
        ctx.pack.info = typeName + " Message (" + std::to_string(msgType) + ")";
    }
}

} // namespace dissect

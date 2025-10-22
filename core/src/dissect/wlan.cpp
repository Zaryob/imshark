#include "wlan.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "protocols.h"
#include "registry.h"
#include "util.h"
#include <network/utils.h>

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;
    using dissect::etherTypeName;
    using dissect::hexString;
    using dissect::le16;
    using dissect::le32;

    std::string mac(const char *p) {
        return network::getMACAddressString(reinterpret_cast<const uint8_t *>(p));
    }

    const char *mgmtSubtypeName(uint8_t subtype) {
        switch (subtype) {
            case 0: return "Association Request";
            case 1: return "Association Response";
            case 2: return "Reassociation Request";
            case 3: return "Reassociation Response";
            case 4: return "Probe Request";
            case 5: return "Probe Response";
            case 6: return "Timing Advertisement";
            case 8: return "Beacon frame";
            case 9: return "ATIM";
            case 10: return "Disassociation";
            case 11: return "Authentication";
            case 12: return "Deauthentication";
            case 13: return "Action";
            case 14: return "Action No Ack";
            default: return "Management";
        }
    }

    const char *ctrlSubtypeName(uint8_t subtype) {
        switch (subtype) {
            case 8: return "Block Ack Request";
            case 9: return "Block Ack";
            case 10: return "Power Save-Poll";
            case 11: return "Request to Send";
            case 12: return "Clear to Send";
            case 13: return "Acknowledgement";
            case 14: return "CF-End";
            case 15: return "CF-End + CF-Ack";
            default: return "Control";
        }
    }

    const char *dataSubtypeName(uint8_t subtype) {
        switch (subtype) {
            case 0: return "Data";
            case 1: return "Data + CF-Ack";
            case 2: return "Data + CF-Poll";
            case 3: return "Data + CF-Ack + CF-Poll";
            case 4: return "Null function (No data)";
            case 5: return "CF-Ack (no data)";
            case 6: return "CF-Poll (no data)";
            case 7: return "CF-Ack + CF-Poll (no data)";
            case 8: return "QoS Data";
            case 9: return "QoS Data + CF-Ack";
            case 10: return "QoS Data + CF-Poll";
            case 11: return "QoS Data + CF-Ack + CF-Poll";
            case 12: return "QoS Null function (No data)";
            case 14: return "QoS CF-Poll (no data)";
            case 15: return "QoS CF-Ack + CF-Poll (no data)";
            default: return "Data";
        }
    }

    const char *typeName(uint8_t type) {
        switch (type) {
            case 0: return "Management frame";
            case 1: return "Control frame";
            case 2: return "Data frame";
            case 3: return "Extension frame";
            default: return "Reserved";
        }
    }

    const char *ieTagName(uint8_t tag) {
        switch (tag) {
            case 0: return "SSID parameter set";
            case 1: return "Supported Rates";
            case 2: return "FH Parameter Set";
            case 3: return "DS Parameter Set";
            case 4: return "CF Parameter Set";
            case 5: return "Traffic Indication Map (TIM)";
            case 6: return "IBSS Parameter Set";
            case 7: return "Country Information";
            case 42: return "ERP Information";
            case 45: return "HT Capabilities";
            case 48: return "RSN Information";
            case 50: return "Extended Supported Rates";
            case 61: return "HT Information";
            case 127: return "Extended Capabilities";
            case 191: return "VHT Capabilities";
            case 192: return "VHT Operation";
            case 221: return "Vendor Specific";
            default: return "Information Element";
        }
    }

    void addFrameControlFields(Field &fcField, uint16_t fc, size_t off) {
        const uint8_t version = fc & 0x03;
        const uint8_t type = (fc >> 2) & 0x03;
        const uint8_t subtype = (fc >> 4) & 0x0F;
        const bool toDs = (fc & 0x0100) != 0;
        const bool fromDs = (fc & 0x0200) != 0;
        const bool moreFrag = (fc & 0x0400) != 0;
        const bool retry = (fc & 0x0800) != 0;
        const bool pwrMgt = (fc & 0x1000) != 0;
        const bool moreData = (fc & 0x2000) != 0;
        const bool protectedFrame = (fc & 0x4000) != 0;
        const bool order = (fc & 0x8000) != 0;

        fcField.add(".... ..00 = Version: " + std::to_string(version), off, 2);
        std::string typeBit = (type == 0 ? "00" : type == 1 ? "01" : type == 2 ? "10" : "11");
        fcField.add(".... " + typeBit + ".. = Type: " + typeName(type) + " (" + std::to_string(type) + ")", off, 2);

        const char *stName = (type == 0 ? mgmtSubtypeName(subtype) : type == 1 ? ctrlSubtypeName(subtype) : dataSubtypeName(subtype));
        fcField.add("Subtype: " + std::to_string(subtype) + " (" + stName + ")", off, 2);

        Field &flags = fcField.add("Flags: " + hexString(fc >> 8, 2), off + 1, 1);
        flags.add(std::string(".... ...") + (toDs ? "1 = To DS: 1" : "0 = To DS: 0"), off + 1, 1);
        flags.add(std::string(".... ..") + (fromDs ? "1. = From DS: 1" : "0. = From DS: 0"), off + 1, 1);
        flags.add(std::string(".... .") + (moreFrag ? "1.. = More Fragments: 1" : "0.. = More Fragments: 0"), off + 1, 1);
        flags.add(std::string(".... ") + (retry ? "1... = Retry: 1" : "0... = Retry: 0"), off + 1, 1);
        flags.add(std::string("... ") + (pwrMgt ? "1.... = Power Management: 1" : "0.... = Power Management: 0"), off + 1, 1);
        flags.add(std::string(".. ") + (moreData ? "1..... = More Data: 1" : "0..... = More Data: 0"), off + 1, 1);
        flags.add(std::string(". ") + (protectedFrame ? "1...... = Protected Flag: 1" : "0...... = Protected Flag: 0"), off + 1, 1);
        flags.add(std::string(order ? "1....... = Order: 1" : "0....... = Order: 0"), off + 1, 1);
    }
} // namespace

void dissect::dissectIeee80211(Context &ctx, const char *data, size_t length) {
    if (length < 10) {
        ctx.markMalformed("frame too short for 802.11 header");
        ctx.pack.protocol = "802.11";
        return;
    }

    const uint16_t fc = le16(data);
    const uint8_t type = (fc >> 2) & 0x03;
    const uint8_t subtype = (fc >> 4) & 0x0F;
    const bool toDs = (fc & 0x0100) != 0;
    const bool fromDs = (fc & 0x0200) != 0;
    const bool protectedFrame = (fc & 0x4000) != 0;
    const bool order = (fc & 0x8000) != 0;

    ctx.pack.wlan_fc = fc;
    ctx.pack.protocol = "802.11";

    const uint16_t duration = le16(data + 2);
    const size_t baseOffset = ctx.offsetOf(data);

    // -----------------------------------------------------------------------------------------
    // Control Frames (Type 1)
    // -----------------------------------------------------------------------------------------
    if (type == 1) {
        if (subtype == 12 || subtype == 13) { // CTS or ACK (10 bytes)
            const std::string ra = mac(data + 4);
            ctx.pack.destination = ra;
            ctx.pack.info = (subtype == 13 ? "Acknowledgement, Receiver address: " : "Clear to Send, Receiver address: ") + ra;

            if (ctx.wantFields()) {
                const char *stName = ctrlSubtypeName(subtype);
                Field &wlan = ctx.addLayer(std::string("IEEE 802.11 ") + stName + ", Receiver address: " + ra, baseOffset, 10);
                Field &fcField = wlan.add("Frame Control Field: " + hexString(fc, 4), baseOffset, 2);
                addFrameControlFields(fcField, fc, baseOffset);
                wlan.add("Duration: " + std::to_string(duration) + " microseconds", baseOffset + 2, 2);
                wlan.add("Receiver address: " + ra, baseOffset + 4, 6);
            }
            return;
        }

        if (length < 16) {
            ctx.markMalformed("truncated 802.11 control frame");
            return;
        }

        const std::string ra = mac(data + 4);
        const std::string ta = mac(data + 10);
        ctx.pack.destination = ra;
        ctx.pack.source = ta;

        size_t ctrlHdrLen = 16;
        if (subtype == 11) { // RTS
            ctx.pack.info = "Request to Send, Receiver: " + ra + ", Transmitter: " + ta;
        } else if (subtype == 10) { // PS-Poll
            ctx.pack.app_text2 = ra; // BSSID
            ctx.pack.info = "Power Save-Poll, BSSID: " + ra;
        } else if (subtype == 8) { // Block Ack Request
            ctx.pack.info = "Block Ack Request";
            if (length >= 20) ctrlHdrLen = 20;
        } else if (subtype == 9) { // Block Ack
            ctx.pack.info = "Block Ack";
            if (length >= 28) ctrlHdrLen = 28;
            else if (length >= 20) ctrlHdrLen = 20;
        } else {
            ctx.pack.info = ctrlSubtypeName(subtype);
        }

        if (ctx.wantFields()) {
            Field &wlan = ctx.addLayer(std::string("IEEE 802.11 ") + ctrlSubtypeName(subtype), baseOffset, std::min(ctrlHdrLen, length));
            Field &fcField = wlan.add("Frame Control Field: " + hexString(fc, 4), baseOffset, 2);
            addFrameControlFields(fcField, fc, baseOffset);
            wlan.add("Duration: " + std::to_string(duration) + " microseconds", baseOffset + 2, 2);
            wlan.add("Receiver address: " + ra, baseOffset + 4, 6);
            wlan.add("Transmitter address: " + ta, baseOffset + 10, 6);
        }
        return;
    }

    // -----------------------------------------------------------------------------------------
    // Management Frames (Type 0)
    // -----------------------------------------------------------------------------------------
    if (type == 0) {
        if (length < 24) {
            ctx.markMalformed("truncated 802.11 management frame header");
            return;
        }

        const std::string da = mac(data + 4);
        const std::string sa = mac(data + 10);
        const std::string bssid = mac(data + 16);
        ctx.pack.destination = da;
        ctx.pack.source = sa;
        ctx.pack.app_text2 = bssid;

        const uint16_t seqCtrl = le16(data + 22);
        const uint16_t seq = (seqCtrl >> 4) & 0x0FFF;
        const uint8_t frag = seqCtrl & 0x0F;
        ctx.pack.wlan_seq = seq;

        size_t bodyOffset = 24;
        std::string ssid;
        uint8_t channel = 0;

        if (subtype == 8 || subtype == 5) { // Beacon (8) or Probe Response (5)
            if (length >= 36) {
                bodyOffset = 36;
            }
        } else if (subtype == 0 || subtype == 2) { // Assoc / Reassoc Request
            if (length >= 28) bodyOffset = 28;
        } else if (subtype == 1 || subtype == 3) { // Assoc / Reassoc Response
            if (length >= 30) bodyOffset = 30;
        }

        // Walk Information Elements
        size_t iePos = bodyOffset;
        while (iePos + 2 <= length) {
            const uint8_t tag = static_cast<uint8_t>(data[iePos]);
            const uint8_t tagLen = static_cast<uint8_t>(data[iePos + 1]);
            if (iePos + 2 + tagLen > length) break;
            if (tag == 0 && ssid.empty()) {
                ssid.assign(data + iePos + 2, tagLen);
                ctx.pack.app_text = ssid;
            } else if (tag == 3 && tagLen >= 1 && channel == 0) {
                channel = static_cast<uint8_t>(data[iePos + 2]);
            }
            iePos += 2 + tagLen;
        }

        // Set Info column
        if (subtype == 8) { // Beacon
            ctx.pack.info = "Beacon frame, SSID: \"" + (ssid.empty() ? "<Broadcast>" : ssid) + "\"";
            if (channel != 0) ctx.pack.info += ", Channel: " + std::to_string(channel);
        } else if (subtype == 4) { // Probe Request
            ctx.pack.info = "Probe Request, SSID: \"" + (ssid.empty() ? "<Broadcast>" : ssid) + "\"";
        } else if (subtype == 5) { // Probe Response
            ctx.pack.info = "Probe Response, SSID: \"" + (ssid.empty() ? "<Broadcast>" : ssid) + "\"";
        } else if (subtype == 0) {
            ctx.pack.info = "Association Request" + (!ssid.empty() ? ", SSID: \"" + ssid + "\"" : "");
        } else if (subtype == 1) {
            const uint16_t status = length >= 28 ? le16(data + 26) : 0;
            ctx.pack.info = "Association Response, Status: " + std::to_string(status);
        } else if (subtype == 10 && length >= 26) {
            ctx.pack.info = "Disassociation, Reason: " + std::to_string(le16(data + 24));
        } else if (subtype == 11 && length >= 28) {
            ctx.pack.info = "Authentication, Seq: " + std::to_string(le16(data + 26));
        } else if (subtype == 12 && length >= 26) {
            ctx.pack.info = "Deauthentication, Reason: " + std::to_string(le16(data + 24));
        } else {
            ctx.pack.info = mgmtSubtypeName(subtype);
        }

        if (ctx.wantFields()) {
            Field &wlan = ctx.addLayer(std::string("IEEE 802.11 ") + mgmtSubtypeName(subtype) + ", Flags: " + hexString(fc >> 8, 2),
                                       baseOffset, std::min<size_t>(length, 24));
            Field &fcField = wlan.add("Frame Control Field: " + hexString(fc, 4), baseOffset, 2);
            addFrameControlFields(fcField, fc, baseOffset);
            wlan.add("Duration: " + std::to_string(duration) + " microseconds", baseOffset + 2, 2);
            wlan.add("Destination address: " + da, baseOffset + 4, 6);
            wlan.add("Source address: " + sa, baseOffset + 10, 6);
            wlan.add("BSS Id: " + bssid, baseOffset + 16, 6);
            Field &sc = wlan.add("Sequence control: " + hexString(seqCtrl, 4) + " (Seq: " + std::to_string(seq) + ", Frag: " + std::to_string(frag) + ")", baseOffset + 22, 2);
            sc.add("Sequence number: " + std::to_string(seq), baseOffset + 22, 2);
            sc.add("Fragment number: " + std::to_string(frag), baseOffset + 22, 2);

            if (length > 24) {
                Field &body = ctx.addLayer("Management Frame Body", baseOffset + 24, length - 24);
                if (subtype == 8 || subtype == 5) {
                    if (length >= 32) body.add("Timestamp: " + std::to_string(le32(data + 24)), baseOffset + 24, 8);
                    if (length >= 34) body.add("Beacon Interval: " + std::to_string(le16(data + 32)), baseOffset + 32, 2);
                    if (length >= 36) body.add("Capability Information: " + hexString(le16(data + 34), 4), baseOffset + 34, 2);
                }
                // Tagged parameters
                size_t tPos = bodyOffset;
                while (tPos + 2 <= length) {
                    const uint8_t tag = static_cast<uint8_t>(data[tPos]);
                    const uint8_t tagLen = static_cast<uint8_t>(data[tPos + 1]);
                    if (tPos + 2 + tagLen > length) break;
                    std::string label = std::string("Tag: ") + ieTagName(tag) + " (" + std::to_string(tag) + "), Length: " + std::to_string(tagLen);
                    if (tag == 0) {
                        label += ": \"" + std::string(data + tPos + 2, tagLen) + "\"";
                    }
                    body.add(std::move(label), baseOffset + tPos, 2 + tagLen);
                    tPos += 2 + tagLen;
                }
            }
        }
        return;
    }

    // -----------------------------------------------------------------------------------------
    // Data Frames (Type 2)
    // -----------------------------------------------------------------------------------------
    const bool isQoS = (subtype & 0x08) != 0;
    const size_t hdrLen = (toDs && fromDs ? 30 : 24) + (isQoS ? 2 : 0) + (order ? 4 : 0);
    if (length < hdrLen) {
        ctx.markMalformed("truncated 802.11 data frame header");
        return;
    }

    std::string ra, ta, da, sa, bssid;
    if (!toDs && !fromDs) {
        da = mac(data + 4); sa = mac(data + 10); bssid = mac(data + 16);
        ra = da; ta = sa;
    } else if (toDs && !fromDs) {
        bssid = mac(data + 4); sa = mac(data + 10); da = mac(data + 16);
        ra = bssid; ta = sa;
    } else if (!toDs && fromDs) {
        da = mac(data + 4); bssid = mac(data + 10); sa = mac(data + 16);
        ra = da; ta = bssid;
    } else { // toDs && fromDs (WDS)
        ra = mac(data + 4); ta = mac(data + 10); da = mac(data + 16); sa = mac(data + 24);
    }

    ctx.pack.destination = !da.empty() ? da : ra;
    ctx.pack.source = !sa.empty() ? sa : ta;
    ctx.pack.app_text2 = bssid;

    const size_t seqOffset = (toDs && fromDs ? 28 : 22);
    const uint16_t seqCtrl = le16(data + seqOffset);
    const uint16_t seq = (seqCtrl >> 4) & 0x0FFF;
    const uint8_t frag = seqCtrl & 0x0F;
    ctx.pack.wlan_seq = seq;

    uint8_t tid = 0;
    size_t qosOffset = 0;
    if (isQoS) {
        qosOffset = (toDs && fromDs ? 30 : 24);
        const uint16_t qosCtrl = le16(data + qosOffset);
        tid = qosCtrl & 0x0F;
    }

    auto addWlanDataLayer = [&]() -> Field & {
        Field &wlan = ctx.addLayer(std::string("IEEE 802.11 ") + dataSubtypeName(subtype) + ", Flags: " + hexString(fc >> 8, 2),
                                   baseOffset, hdrLen);
        Field &fcField = wlan.add("Frame Control Field: " + hexString(fc, 4), baseOffset, 2);
        addFrameControlFields(fcField, fc, baseOffset);
        wlan.add("Duration: " + std::to_string(duration) + " microseconds", baseOffset + 2, 2);
        wlan.add("Receiver address: " + ra, baseOffset + 4, 6);
        wlan.add("Transmitter address: " + ta, baseOffset + 10, 6);
        if (!da.empty() && da != ra) wlan.add("Destination address: " + da, baseOffset + (toDs && !fromDs ? 16 : 4), 6);
        if (!sa.empty() && sa != ta) wlan.add("Source address: " + sa, baseOffset + (!toDs && fromDs ? 16 : 10), 6);
        if (!bssid.empty()) wlan.add("BSS Id: " + bssid, baseOffset + (!toDs && !fromDs ? 16 : !toDs && fromDs ? 10 : 4), 6);

        Field &sc = wlan.add("Sequence control: " + hexString(seqCtrl, 4) + " (Seq: " + std::to_string(seq) + ", Frag: " + std::to_string(frag) + ")", baseOffset + seqOffset, 2);
        sc.add("Sequence number: " + std::to_string(seq), baseOffset + seqOffset, 2);
        sc.add("Fragment number: " + std::to_string(frag), baseOffset + seqOffset, 2);

        if (isQoS) {
            Field &qc = wlan.add("QoS Control: TID " + std::to_string(tid) + " (Priority: " + std::to_string(tid) + ")", baseOffset + qosOffset, 2);
            qc.add("Traffic Identifier: " + std::to_string(tid), baseOffset + qosOffset, 2);
        }
        return wlan;
    };

    // 1. Protected Data
    if (protectedFrame) {
        ctx.pack.info = (isQoS ? "QoS Data" : "Data") + std::string(", Protected (encrypted)");
        if (ctx.wantFields()) {
            addWlanDataLayer();
            if (length > hdrLen) {
                ctx.addLayer("Protected payload (" + std::to_string(length - hdrLen) + " bytes)", baseOffset + hdrLen, length - hdrLen);
            }
        }
        return;
    }

    // 2. Null function frames
    if (subtype == 4 || subtype == 12) {
        ctx.pack.info = isQoS ? "QoS Null function (No data)" : "Null function (No data)";
        if (ctx.wantFields()) {
            addWlanDataLayer();
        }
        return;
    }

    // 3. Data without payload
    if (length <= hdrLen) {
        ctx.pack.info = std::string(isQoS ? "QoS Data" : "Data") + ", SN=" + std::to_string(seq);
        if (ctx.wantFields()) {
            addWlanDataLayer();
        }
        return;
    }

    // 4. Cleartext Data with payload: check LLC/SNAP
    const size_t payloadLen = length - hdrLen;
    const char *payload = data + hdrLen;

    if (payloadLen >= 8 && static_cast<uint8_t>(payload[0]) == 0xAA &&
        static_cast<uint8_t>(payload[1]) == 0xAA && static_cast<uint8_t>(payload[2]) == 0x03) {
        const uint32_t oui = (static_cast<uint8_t>(payload[3]) << 16) | (static_cast<uint8_t>(payload[4]) << 8) | static_cast<uint8_t>(payload[5]);
        const uint16_t etherType = be16(payload + 6);
        ctx.pack.has_llc = 1;
        ctx.pack.has_snap = 1;

        if (ctx.wantFields()) {
            addWlanDataLayer();
            Field &llc = ctx.addLayer("Logical-Link Control", baseOffset + hdrLen, 8);
            llc.add("DSAP: SNAP (0xaa)", baseOffset + hdrLen, 1);
            llc.add("SSAP: SNAP (0xaa)", baseOffset + hdrLen + 1, 1);
            llc.add("Control field: Unnumbered Information (0x03)", baseOffset + hdrLen + 2, 1);
            llc.add("Organization Code: " + hexString(oui, 6), baseOffset + hdrLen + 3, 3);
            llc.add("Type: " + etherTypeName(etherType) + " (" + hexString(etherType, 4) + ")", baseOffset + hdrLen + 6, 2);
        }

        ctx.pack.l2_size = static_cast<uint16_t>(hdrLen + 8);
        ctx.pack.ether_type = etherType;

        if (const Dissector *inner = ctx.registry.findEtherType(etherType)) {
            (*inner)(ctx, payload + 8, payloadLen - 8);
            return;
        }

        // Fallback for unsupported EtherType
        ctx.pack.info = std::string(isQoS ? "QoS Data" : "Data") + ", EtherType 0x" + hexString(etherType, 4);
        if (ctx.wantFields() && payloadLen > 8) {
            ctx.addLayer("Data (" + std::to_string(payloadLen - 8) + " bytes)", baseOffset + hdrLen + 8, payloadLen - 8);
        }
        return;
    }

    // Raw data without LLC/SNAP
    ctx.pack.info = std::string(isQoS ? "QoS Data" : "Data") + " (" + std::to_string(payloadLen) + " bytes)";
    if (ctx.wantFields()) {
        addWlanDataLayer();
        ctx.addLayer("Data (" + std::to_string(payloadLen) + " bytes)", baseOffset + hdrLen, payloadLen);
    }
}

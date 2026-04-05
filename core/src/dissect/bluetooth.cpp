#include "bluetooth.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *hciH4PacketTypeName(uint8_t type) {
    switch (type) {
        case 1: return "HCI Command";
        case 2: return "HCI ACL Data";
        case 3: return "HCI SCO Data";
        case 4: return "HCI Event";
        case 5: return "HCI ISO Data";
        default: return "Unknown";
    }
}

const char *hciEventName(uint8_t ev) {
    switch (ev) {
        case 0x01: return "Inquiry Complete";
        case 0x02: return "Inquiry Result";
        case 0x03: return "Connection Complete";
        case 0x04: return "Connection Request";
        case 0x05: return "Disconnection Complete";
        case 0x06: return "Authentication Complete";
        case 0x0e: return "Command Complete";
        case 0x0f: return "Command Status";
        case 0x13: return "Number Of Completed Packets";
        case 0x3e: return "LE Meta Event";
        default: return nullptr;
    }
}

const char *attOpcodeName(uint8_t op) {
    switch (op) {
        case 0x01: return "Error Response";
        case 0x02: return "Exchange MTU Request";
        case 0x03: return "Exchange MTU Response";
        case 0x04: return "Find Information Request";
        case 0x05: return "Find Information Response";
        case 0x06: return "Find By Type Value Request";
        case 0x07: return "Find By Type Value Response";
        case 0x08: return "Read By Type Request";
        case 0x09: return "Read By Type Response";
        case 0x0a: return "Read Request";
        case 0x0b: return "Read Response";
        case 0x10: return "Read Multiple Request";
        case 0x11: return "Read Multiple Response";
        case 0x12: return "Write Request";
        case 0x13: return "Write Response";
        case 0x16: return "Prepare Write Request";
        case 0x17: return "Prepare Write Response";
        case 0x18: return "Execute Write Request";
        case 0x19: return "Execute Write Response";
        case 0x1b: return "Handle Value Notification";
        case 0x1d: return "Handle Value Indication";
        case 0x1e: return "Handle Value Confirmation";
        case 0x52: return "Write Command";
        default: return nullptr;
    }
}
const char *monitorOpcodeName(uint16_t op) {
    switch (op) {
        case 0: return "New Index";
        case 1: return "Delete Index";
        case 2: return "Command Packet";
        case 3: return "Event Packet";
        case 4: return "ACL TX Packet";
        case 5: return "ACL RX Packet";
        case 6: return "SCO TX Packet";
        case 7: return "SCO RX Packet";
        case 8: return "Open Index";
        case 9: return "Close Index";
        case 10: return "Index Info";
        case 11: return "Vendor Diagnostic";
        case 12: return "System Note";
        case 13: return "User Logging";
        case 14: return "Control Open";
        case 15: return "Control Close";
        case 16: return "Control Command";
        case 17: return "Control Event";
        case 18: return "ISO TX Packet";
        case 19: return "ISO RX Packet";
        default: return nullptr;
    }
}

uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

// Where an HCI packet travels. H4 captures carry no direction: commands always go to the controller and events always
// come from it, only ACL/SCO/ISO data is ambiguous (shown as sent by the host).
enum class Flow { Unknown, ToController, FromController };

void setEndpoints(Context &ctx, const std::string &host, const std::string &remote, bool hostIsSource) {
    ctx.pack.source = hostIsSource ? host : remote;
    ctx.pack.destination = hostIsSource ? remote : host;
}

// L2CAP and what it carries. `data` holds the bytes of the L2CAP PDU that are present, `off` is their absolute offset.
// Returns true when the PDU is malformed (its length field promises more than the ACL packet holds).
bool dissectL2cap(Context &ctx, const uint8_t *data, size_t len, size_t off) {
    if (len < 4) return false;
    const uint16_t length = le16(data);
    const uint16_t cid = le16(data + 2);
    const size_t have = len - 4;
    const bool truncated = length > have;
    const size_t payloadLen = truncated ? have : length;

    std::string cidName;
    switch (cid) {
        case 0x0001: cidName = "Signaling Channel"; break;
        case 0x0002: cidName = "Connectionless"; break;
        case 0x0004: cidName = "Attribute Protocol (ATT)"; break;
        case 0x0005: cidName = "LE Signaling"; break;
        case 0x0006: cidName = "Security Manager (SMP)"; break;
        default:
            if (cid >= 0x0040) cidName = "Dynamic CID " + hexString(cid, 4);
            else cidName = "Reserved CID " + hexString(cid, 4);
            break;
    }

    if (ctx.wantFields()) {
        auto &lNode = ctx.addLayer("Bluetooth L2CAP (" + cidName + ")", off, 4 + payloadLen);
        lNode.add("Length: " + std::to_string(length), off, 2);
        lNode.add("CID: " + hexString(cid, 4) + " (" + cidName + ")", off + 2, 2);
    }

    // ATT Protocol (CID 0x0004)
    if (cid == 0x0004 && payloadLen > 0) {
        const uint8_t *att = data + 4;
        const uint8_t attOp = att[0];
        const char *opStr = attOpcodeName(attOp);
        const std::string opName = opStr ? opStr : ("Opcode " + hexString(attOp, 2));

        ctx.pack.protocol = "ATT";
        ctx.pack.info = "ATT " + opName;

        // The Info column and the detail pane are built from the same values
        std::string paramText, paramName;
        size_t paramOff = 1, paramLen = 0;
        if ((attOp == 0x02 || attOp == 0x03) && payloadLen >= 3) { // Exchange MTU Request / Response
            const uint16_t mtu = le16(att + 1);
            paramName = attOp == 0x02 ? "Client Rx MTU: " : "Server Rx MTU: ";
            paramText = std::to_string(mtu);
            paramLen = 2;
            ctx.pack.info += " (MTU: " + paramText + ")";
        } else if ((attOp == 0x12 || attOp == 0x52 || attOp == 0x1b || attOp == 0x1d) && payloadLen >= 3) {
            const uint16_t handle = le16(att + 1);
            paramName = "Handle: ";
            paramText = hexString(handle, 4);
            paramLen = 2;
            ctx.pack.info += " Handle: " + paramText;
        }

        if (ctx.wantFields()) {
            auto &attNode = ctx.addLayer("Bluetooth Attribute Protocol (" + opName + ")", off + 4, payloadLen);
            attNode.add("Opcode: " + opName + " (" + hexString(attOp, 2) + ")", off + 4, 1);
            if (paramLen) attNode.add(paramName + paramText, off + 4 + paramOff, paramLen);
        }
    } else {
        ctx.pack.protocol = "L2CAP";
        ctx.pack.info = "L2CAP " + cidName + " (Len " + std::to_string(length) + ")";
    }
    return truncated;
}

// One HCI packet. `body` points to the bytes after the packet type indicator and `off` is their absolute offset in the
// frame; `typeByte` says whether the indicator itself is part of the frame (H4: yes, Linux monitor: no, the opcode of
// its header tells the type). `controller` names the Bluetooth controller (monitor: "hciN", H4: "controller").
void dissectHci(Context &ctx, uint8_t pktType, const uint8_t *body, size_t n, size_t off, bool typeByte,
                const std::string &controller, Flow flow) {
    const char *typeName = hciH4PacketTypeName(pktType);
    const size_t start = typeByte ? off - 1 : off;
    const size_t extra = typeByte ? 1 : 0;

    ctx.pack.protocol = "HCI";
    ctx.pack.app_type = pktType;

    auto truncated = [&](const char *what) {
        ctx.pack.info = std::string("HCI ") + typeName;
        setEndpoints(ctx, "host", controller, pktType != 4 && flow != Flow::FromController);
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer(std::string("Bluetooth HCI (") + typeName + ")", start, n + extra);
            root.add(std::string("Packet Type: ") + typeName + " (" + std::to_string(pktType) + ")", start, extra);
        }
        ctx.markMalformed(what);
    };

    if (pktType == 1) { // Command: opcode (2), parameter length (1)
        if (n < 3) return truncated("Truncated HCI command");
        const uint16_t opcode = le16(body);
        const uint8_t paramLen = body[2];
        const uint16_t ocf = opcode & 0x03ff;
        const uint16_t ogf = (opcode >> 10) & 0x3f;
        const bool bad = paramLen > n - 3;
        setEndpoints(ctx, "host", controller, true);
        ctx.pack.info = "HCI Command: OGF " + hexString(ogf, 2) + ", OCF " + hexString(ocf, 3);
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI Command (" + hexString(opcode, 4) + ")", start,
                                      extra + (bad ? n : 3 + paramLen));
            root.add("Packet Type: HCI Command (1)", start, extra);
            root.add("Opcode: " + hexString(opcode, 4), off, 2);
            root.add("OGF: " + hexString(ogf, 2), off, 2);
            root.add("OCF: " + hexString(ocf, 3), off, 2);
            root.add("Parameter Length: " + std::to_string(paramLen), off + 2, 1);
        }
        if (bad) ctx.markMalformed("HCI command parameter length exceeds the packet");
    } else if (pktType == 4) { // Event: event code (1), parameter length (1)
        if (n < 2) return truncated("Truncated HCI event");
        const uint8_t eventCode = body[0];
        const uint8_t paramLen = body[1];
        const char *evName = hciEventName(eventCode);
        const std::string evStr = evName ? evName : ("Event " + hexString(eventCode, 2));
        const bool bad = paramLen > n - 2;
        setEndpoints(ctx, "host", controller, false);
        ctx.pack.info = "HCI Event: " + evStr;
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI Event (" + evStr + ")", start, extra + (bad ? n : 2 + paramLen));
            root.add("Packet Type: HCI Event (4)", start, extra);
            root.add("Event Code: " + evStr + " (" + hexString(eventCode, 2) + ")", off, 1);
            root.add("Parameter Length: " + std::to_string(paramLen), off + 1, 1);
        }
        if (bad) ctx.markMalformed("HCI event parameter length exceeds the packet");
    } else if (pktType == 2) { // ACL data: handle and flags (2), data length (2)
        if (n < 4) return truncated("Truncated HCI ACL header");
        const uint16_t handleFlags = le16(body);
        const uint16_t dataLen = le16(body + 2);
        const uint16_t handle = handleFlags & 0x0FFF;
        const uint8_t pbFlag = (handleFlags >> 12) & 0x03;
        const uint8_t bcFlag = (handleFlags >> 14) & 0x03;
        const size_t have = n - 4;
        const bool bad = dataLen > have;
        const size_t dataPresent = bad ? have : dataLen;

        // The remote device of an ACL link is named by its connection handle
        const std::string handleStr = hexString(handle, 4);
        setEndpoints(ctx, "host", handleStr, flow != Flow::FromController);

        ctx.pack.info = "HCI ACL Data (Handle " + hexString(handle, 3) + ", Len " + std::to_string(dataLen) + ")";
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI ACL Data", start, extra + 4);
            root.add("Packet Type: HCI ACL (2)", start, extra);
            root.add("Connection Handle: " + hexString(handle, 3), off, 2);
            root.add("PB Flag: " + std::to_string(pbFlag), off, 2);
            root.add("BC Flag: " + std::to_string(bcFlag), off, 2);
            root.add("Data Length: " + std::to_string(dataLen), off + 2, 2);
        }

        bool l2capBad = false;
        if (dataPresent > 0) {
            if (pbFlag == 1) { // continuation of an L2CAP PDU started in an earlier ACL packet: no L2CAP header here
                ctx.pack.protocol = "L2CAP";
                ctx.pack.info = "L2CAP Continuation Fragment (Handle " + hexString(handle, 3) + ", " +
                                std::to_string(dataPresent) + " bytes)";
                if (ctx.wantFields()) ctx.addLayer("Bluetooth L2CAP Continuation Fragment", off + 4, dataPresent);
            } else if (dataPresent >= 4) {
                l2capBad = dissectL2cap(ctx, body + 4, dataPresent, off + 4);
            } else {
                ctx.markMalformed("L2CAP header truncated");
            }
        }
        if (bad) ctx.markMalformed("ACL data length exceeds the packet");
        else if (l2capBad) ctx.markMalformed("L2CAP length exceeds the data in the ACL packet");
    } else {
        setEndpoints(ctx, "host", controller, flow != Flow::FromController);
        ctx.pack.info = std::string("HCI ") + typeName;
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer(std::string("Bluetooth HCI (") + typeName + ")", start, n + extra);
            root.add(std::string("Packet Type: ") + typeName + " (" + std::to_string(pktType) + ")", start, extra);
        }
    }
}

} // namespace

void dissectBluetoothHciH4(Context &ctx, const char *data, size_t length) {
    if (!data || length < 1) {
        ctx.pack.protocol = "HCI";
        ctx.markMalformed("Empty Bluetooth HCI packet");
        return;
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    dissectHci(ctx, bytes[0], bytes + 1, length - 1, ctx.offsetOf(data) + 1, true, "controller", Flow::Unknown);
}

void dissectBluetoothLinuxMonitor(Context &ctx, const char *data, size_t length) {
    // pcap pseudo header (libpcap pcap-bt-monitor-linux.c): adapter id and opcode, 2 bytes each, network byte order
    if (!data || length < 4) {
        ctx.pack.protocol = "BT Mon";
        ctx.markMalformed("Truncated Bluetooth Linux Monitor header");
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const uint16_t adapter = static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
    const uint16_t opcode = static_cast<uint16_t>((bytes[2] << 8) | bytes[3]);
    const char *opName = monitorOpcodeName(opcode);
    const std::string opStr = opName ? opName : ("Opcode " + hexString(opcode, 4));
    const std::string controller = "hci" + std::to_string(adapter);
    const size_t o = ctx.offsetOf(data);

    ctx.pack.protocol = "BT Mon";
    ctx.pack.info = "BT Mon " + controller + " " + opStr;
    setEndpoints(ctx, "host", controller, true);

    if (ctx.wantFields()) {
        auto &root = ctx.addLayer("Bluetooth Linux Monitor", o, 4);
        root.add("Adapter ID: " + std::to_string(adapter), o, 2);
        root.add("Opcode: " + opStr + " (" + std::to_string(opcode) + ")", o + 2, 2);
    }

    const uint8_t *payload = bytes + 4;
    const size_t pLen = length - 4;
    uint8_t type = 0;
    Flow flow = Flow::Unknown;
    switch (opcode) {
        case 2: type = 1; flow = Flow::ToController; break;   // command
        case 3: type = 4; flow = Flow::FromController; break; // event
        case 4: type = 2; flow = Flow::ToController; break;   // ACL TX
        case 5: type = 2; flow = Flow::FromController; break; // ACL RX
        case 6: type = 3; flow = Flow::ToController; break;   // SCO TX
        case 7: type = 3; flow = Flow::FromController; break; // SCO RX
        case 18: type = 5; flow = Flow::ToController; break;  // ISO TX
        case 19: type = 5; flow = Flow::FromController; break;// ISO RX
        default: return;
    }
    dissectHci(ctx, type, payload, pLen, o + 4, false, controller, flow);
}

namespace {

const char *wpanFrameTypeName(uint8_t t) {
    switch (t) { // IEEE 802.15.4-2015 table 7-1
        case 0: return "Beacon";
        case 1: return "Data";
        case 2: return "Acknowledgment";
        case 3: return "MAC Command";
        case 5: return "Multipurpose";
        case 6: return "Fragment";
        case 7: return "Extended";
        default: return "Reserved";
    }
}

// The MAC frame: `base` is the absolute offset of data[0]. A frame check sequence of `fcsLen` bytes ends it.
void dissectWpanMac(Context &ctx, const uint8_t *bytes, size_t length, size_t base, size_t fcsLen) {
    if (length < 3 + fcsLen) {
        ctx.pack.protocol = "802.15.4";
        ctx.markMalformed("Truncated IEEE 802.15.4 frame");
        return;
    }
    const size_t macLen = length - fcsLen;
    const uint16_t fcf = le16(bytes);
    const uint8_t seqNo = bytes[2];

    const uint8_t frameType = fcf & 0x07;
    const bool secEnabled = (fcf & 0x08) != 0;
    const bool framePending = (fcf & 0x10) != 0;
    const bool ackReq = (fcf & 0x20) != 0;
    const bool panIdComp = (fcf & 0x40) != 0;
    const uint8_t dstAddrMode = (fcf >> 10) & 0x03;
    const uint8_t frameVer = (fcf >> 12) & 0x03;
    const uint8_t srcAddrMode = (fcf >> 14) & 0x03;
    const char *typeName = wpanFrameTypeName(frameType);

    ctx.pack.protocol = "802.15.4";
    ctx.pack.app_type = frameType;

    std::string summary = std::string(typeName) + " (Seq " + std::to_string(seqNo) + ")";
    if (ackReq) summary += " [ACK Req]";
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        auto &root = ctx.addLayer("IEEE 802.15.4 (" + std::string(typeName) + ")", base, macLen);
        root.add("Frame Control: " + hexString(fcf, 4), base, 2);
        root.add("Frame Type: " + std::string(typeName) + " (" + std::to_string(frameType) + ")", base, 2);
        root.add("Security Enabled: " + std::string(secEnabled ? "Yes" : "No"), base, 2);
        root.add("Frame Pending: " + std::string(framePending ? "Yes" : "No"), base, 2);
        root.add("Acknowledgment Request: " + std::string(ackReq ? "Yes" : "No"), base, 2);
        root.add("PAN ID Compression: " + std::string(panIdComp ? "Yes" : "No"), base, 2);
        root.add("Destination Addressing Mode: " + std::to_string(dstAddrMode), base, 2);
        root.add("Frame Version: " + std::to_string(frameVer), base, 2);
        root.add("Source Addressing Mode: " + std::to_string(srcAddrMode), base, 2);
        root.add("Sequence Number: " + std::to_string(seqNo), base + 2, 1);
        if (fcsLen == 2) {
            const uint16_t fcs = le16(bytes + macLen);
            ctx.addLayer("Frame Check Sequence: " + hexString(fcs, 4) + " [unverified]", base + macLen, 2);
        }
    }
}

} // namespace

void dissectIeee802154(Context &ctx, const char *data, size_t length) {
    if (!data) return;
    dissectWpanMac(ctx, reinterpret_cast<const uint8_t *>(data), length, ctx.offsetOf(data), 0);
}

// LINKTYPE_IEEE802_15_4_WITHFCS (195): the 16-bit FCS ends the frame, unless the capture header already cut it off
void dissectIeee802154WithFcs(Context &ctx, const char *data, size_t length) {
    if (!data) return;
    const size_t fcs = ctx.pack.fcs_length != 0 ? 0 : 2;
    dissectWpanMac(ctx, reinterpret_cast<const uint8_t *>(data), length, ctx.offsetOf(data), fcs);
}

// LINKTYPE_IEEE802_15_4_NONASK_PHY (215): 4 byte preamble, start of frame delimiter (0xA7), PHY header (7 bit frame
// length, which counts the MAC frame including its FCS), then the MAC frame
void dissectIeee802154NonaskPhy(Context &ctx, const char *data, size_t length) {
    if (!data || length < 6) {
        ctx.pack.protocol = "802.15.4";
        ctx.markMalformed("Truncated IEEE 802.15.4 PHY header");
        return;
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t o = ctx.offsetOf(data);
    const uint8_t sfd = bytes[4];
    const uint8_t phr = bytes[5];
    const size_t frameLen = phr & 0x7F;
    const size_t have = length - 6;
    const size_t macLen = frameLen < have ? frameLen : have;

    if (ctx.wantFields()) {
        auto &phy = ctx.addLayer("IEEE 802.15.4 PHY (non-ASK)", o, 6);
        phy.add("Preamble: " + hexString((uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) | (uint32_t(bytes[2]) << 8) | bytes[3], 8), o, 4);
        phy.add("Start of Frame Delimiter: " + hexString(sfd, 2), o + 4, 1);
        phy.add("Frame Length: " + std::to_string(frameLen), o + 5, 1);
    }
    dissectWpanMac(ctx, bytes + 6, macLen, o + 6, 2);
    if (frameLen > have) ctx.markMalformed("PHY frame length exceeds the packet");
}

} // namespace dissect

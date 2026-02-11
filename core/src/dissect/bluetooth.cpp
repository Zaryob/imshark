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

// Dissects L2CAP layer inside ACL data
void dissectL2cap(Context &ctx, const uint8_t *l2capBytes, size_t l2capLen, size_t fileOffset) {
    if (l2capLen < 4) return;
    ByteReader r(l2capBytes, l2capLen);
    uint16_t length = r.u16_le();
    uint16_t cid = r.u16_le();

    std::string cidName;
    switch (cid) {
        case 0x0001: cidName = "Signaling Channel"; break;
        case 0x0002: cidName = "Connectionless"; break;
        case 0x0004: cidName = "Attribute Protocol (ATT)"; break;
        case 0x0005: cidName = "LE Signaling"; break;
        case 0x0006: cidName = "Security Manager (SMP)"; break;
        default:
            if (cid >= 0x0040) cidName = "Dynamic CID 0x" + hexString(cid, 4);
            else cidName = "Reserved CID 0x" + hexString(cid, 4);
            break;
    }

    if (ctx.wantFields()) {
        auto &lNode = ctx.addLayer("Bluetooth L2CAP (" + cidName + ")", fileOffset, 4);
        lNode.add("Length: " + std::to_string(length));
        lNode.add("CID: 0x" + hexString(cid, 4) + " (" + cidName + ")");
    }

    // ATT Protocol (CID 0x0004)
    if (cid == 0x0004 && r.remaining() > 0) {
        uint8_t attOp = r.u8();
        const char *opStr = attOpcodeName(attOp);
        std::string opName = opStr ? opStr : ("Opcode 0x" + hexString(attOp, 2));

        ctx.pack.protocol = "ATT";
        ctx.pack.info = "ATT " + opName;

        if (ctx.wantFields()) {
            auto &attNode = ctx.addLayer("Bluetooth Attribute Protocol (" + opName + ")", fileOffset + 4, l2capLen - 4);
            attNode.add("Opcode: " + opName + " (0x" + hexString(attOp, 2) + ")");
            if (attOp == 0x02 && r.remaining() >= 2) { // Exchange MTU Request
                uint16_t clientMtu = r.u16_le();
                attNode.add("Client Rx MTU: " + std::to_string(clientMtu));
                ctx.pack.info += " (MTU: " + std::to_string(clientMtu) + ")";
            } else if (attOp == 0x03 && r.remaining() >= 2) { // Exchange MTU Response
                uint16_t serverMtu = r.u16_le();
                attNode.add("Server Rx MTU: " + std::to_string(serverMtu));
                ctx.pack.info += " (MTU: " + std::to_string(serverMtu) + ")";
            } else if ((attOp == 0x12 || attOp == 0x52 || attOp == 0x1b || attOp == 0x1d) && r.remaining() >= 2) {
                uint16_t handle = r.u16_le();
                attNode.add("Handle: 0x" + hexString(handle, 4));
                ctx.pack.info += " Handle: 0x" + hexString(handle, 4);
            }
        }
    } else {
        ctx.pack.protocol = "L2CAP";
        ctx.pack.info = "L2CAP " + cidName + " (Len " + std::to_string(length) + ")";
    }
}

} // namespace

void dissectBluetoothHciH4(Context &ctx, const char *data, size_t length) {
    if (!data || length < 1) {
        ctx.markMalformed("Empty Bluetooth HCI packet");
        ctx.pack.protocol = "HCI";
        ctx.pack.info = "HCI [Empty]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    uint8_t pktType = bytes[0];
    const char *typeName = hciH4PacketTypeName(pktType);

    ctx.pack.protocol = "HCI";
    ctx.pack.app_type = pktType;

    size_t o = ctx.offsetOf(data);

    if (pktType == 1 && length >= 4) { // HCI Command: OCF/OGF (2 bytes), param len (1 byte)
        uint16_t opcode = static_cast<uint16_t>(bytes[1]) | (static_cast<uint16_t>(bytes[2]) << 8);
        uint8_t paramLen = bytes[3];
        uint16_t ocf = opcode & 0x03ff;
        uint16_t ogf = (opcode >> 10) & 0x3f;

        ctx.pack.info = "HCI Command: OGF 0x" + hexString(ogf, 2) + ", OCF 0x" + hexString(ocf, 3);
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI Command (0x" + hexString(opcode, 4) + ")", o, 4 + paramLen <= length ? 4 + paramLen : length);
            root.add("Packet Type: HCI Command (1)");
            root.add("Opcode: 0x" + hexString(opcode, 4));
            root.add("OGF: 0x" + hexString(ogf, 2));
            root.add("OCF: 0x" + hexString(ocf, 3));
            root.add("Parameter Length: " + std::to_string(paramLen));
        }
    } else if (pktType == 4 && length >= 3) { // HCI Event: event code (1 byte), param len (1 byte)
        uint8_t eventCode = bytes[1];
        uint8_t paramLen = bytes[2];
        const char *evName = hciEventName(eventCode);
        std::string evStr = evName ? evName : ("Event 0x" + hexString(eventCode, 2));

        ctx.pack.info = "HCI Event: " + evStr;
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI Event (" + evStr + ")", o, 3 + paramLen <= length ? 3 + paramLen : length);
            root.add("Packet Type: HCI Event (4)");
            root.add("Event Code: " + evStr + " (0x" + hexString(eventCode, 2) + ")");
            root.add("Parameter Length: " + std::to_string(paramLen));
        }
    } else if (pktType == 2 && length >= 5) { // HCI ACL Data: Handle/Flags (2 bytes), data len (2 bytes)
        uint16_t handleFlags = static_cast<uint16_t>(bytes[1]) | (static_cast<uint16_t>(bytes[2]) << 8);
        uint16_t dataLen = static_cast<uint16_t>(bytes[3]) | (static_cast<uint16_t>(bytes[4]) << 8);
        uint16_t handle = handleFlags & 0x0FFF;
        uint8_t pbFlag = (handleFlags >> 12) & 0x03;
        uint8_t bcFlag = (handleFlags >> 14) & 0x03;

        ctx.pack.info = "HCI ACL Data (Handle 0x" + hexString(handle, 3) + ", Len " + std::to_string(dataLen) + ")";
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI ACL Data", o, 5);
            root.add("Packet Type: HCI ACL (2)");
            root.add("Connection Handle: 0x" + hexString(handle, 3));
            root.add("PB Flag: " + std::to_string(pbFlag));
            root.add("BC Flag: " + std::to_string(bcFlag));
            root.add("Data Length: " + std::to_string(dataLen));
        }

        // Inner L2CAP payload
        if (length >= 5 + 4) {
            dissectL2cap(ctx, bytes + 5, length - 5, o + 5);
        }
    } else {
        ctx.pack.info = "HCI " + std::string(typeName);
        if (ctx.wantFields()) {
            auto &root = ctx.addLayer("Bluetooth HCI (" + std::string(typeName) + ")", o, length);
            root.add("Packet Type: " + std::string(typeName) + " (" + std::to_string(pktType) + ")");
        }
    }
}

void dissectBluetoothLinuxMonitor(Context &ctx, const char *data, size_t length) {
    if (!data || length < 6) {
        ctx.markMalformed("Truncated Bluetooth Linux Monitor header");
        ctx.pack.protocol = "BT Mon";
        ctx.pack.info = "BT Mon [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint16_t adapter = r.u16_le();
    uint16_t opcode = r.u16_le();
    uint16_t payloadLen = r.u16_le();

    ctx.pack.protocol = "BT Mon";
    ctx.pack.info = "BT Mon Adapter " + std::to_string(adapter) + " Opcode 0x" + hexString(opcode, 4);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Bluetooth Linux Monitor", o, 6);
        root.add("Adapter: " + std::to_string(adapter));
        root.add("Opcode: 0x" + hexString(opcode, 4));
        root.add("Payload Length: " + std::to_string(payloadLen));
    }

    // Common opcodes: 0 = new index, 1 = del index, 2 = command packet, 3 = event packet, 4 = acl tx, 5 = acl rx
    if (length > 6) {
        const char *payload = data + 6;
        size_t pLen = length - 6;
        if (opcode == 2) { // Command packet
            std::string pseudoH4;
            pseudoH4.push_back(1); // HCI Command indicator
            pseudoH4.append(payload, pLen);
            dissectBluetoothHciH4(ctx, pseudoH4.data(), pseudoH4.size());
        } else if (opcode == 3) { // Event packet
            std::string pseudoH4;
            pseudoH4.push_back(4); // HCI Event indicator
            pseudoH4.append(payload, pLen);
            dissectBluetoothHciH4(ctx, pseudoH4.data(), pseudoH4.size());
        } else if (opcode == 4 || opcode == 5) { // ACL packet
            std::string pseudoH4;
            pseudoH4.push_back(2); // HCI ACL indicator
            pseudoH4.append(payload, pLen);
            dissectBluetoothHciH4(ctx, pseudoH4.data(), pseudoH4.size());
        }
    }
}

void dissectIeee802154(Context &ctx, const char *data, size_t length) {
    if (!data || length < 3) {
        ctx.markMalformed("Truncated IEEE 802.15.4 frame");
        ctx.pack.protocol = "802.15.4";
        ctx.pack.info = "802.15.4 [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint16_t fcf = r.u16_le();
    uint8_t seqNo = r.u8();

    uint8_t frameType = fcf & 0x07;
    bool secEnabled = (fcf & 0x08) != 0;
    bool framePending = (fcf & 0x10) != 0;
    bool ackReq = (fcf & 0x20) != 0;
    bool panIdComp = (fcf & 0x40) != 0;
    uint8_t dstAddrMode = (fcf >> 10) & 0x03;
    uint8_t frameVer = (fcf >> 12) & 0x03;
    uint8_t srcAddrMode = (fcf >> 14) & 0x03;

    const char *typeName = "Reserved";
    switch (frameType) {
        case 0: typeName = "Beacon"; break;
        case 1: typeName = "Data"; break;
        case 2: typeName = "Acknowledgment"; break;
        case 3: typeName = "MAC Command"; break;
        default: break;
    }

    ctx.pack.protocol = "802.15.4";
    ctx.pack.app_type = frameType;

    std::string summary = std::string(typeName) + " (Seq " + std::to_string(seqNo) + ")";
    if (ackReq) summary += " [ACK Req]";

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("IEEE 802.15.4 (" + std::string(typeName) + ")", o, length);
        root.add("Frame Control: 0x" + hexString(fcf, 4));
        root.add("Frame Type: " + std::string(typeName) + " (" + std::to_string(frameType) + ")");
        root.add("Security Enabled: " + std::string(secEnabled ? "Yes" : "No"));
        root.add("Frame Pending: " + std::string(framePending ? "Yes" : "No"));
        root.add("Acknowledgment Request: " + std::string(ackReq ? "Yes" : "No"));
        root.add("PAN ID Compression: " + std::string(panIdComp ? "Yes" : "No"));
        root.add("Destination Addressing Mode: " + std::to_string(dstAddrMode));
        root.add("Frame Version: " + std::to_string(frameVer));
        root.add("Source Addressing Mode: " + std::to_string(srcAddrMode));
        root.add("Sequence Number: " + std::to_string(seqNo));
    }
}

} // namespace dissect

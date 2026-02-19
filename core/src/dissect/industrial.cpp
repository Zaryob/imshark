#include "industrial.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *modbusFunctionName(uint8_t fn) {
    switch (fn & 0x7F) {
        case 1: return "Read Coils";
        case 2: return "Read Discrete Inputs";
        case 3: return "Read Holding Registers";
        case 4: return "Read Input Registers";
        case 5: return "Write Single Coil";
        case 6: return "Write Single Register";
        case 7: return "Read Exception Status";
        case 8: return "Diagnostics";
        case 11: return "Get Comm Event Counter";
        case 12: return "Get Comm Event Log";
        case 15: return "Write Multiple Coils";
        case 16: return "Write Multiple Registers";
        case 17: return "Report Server ID";
        case 20: return "Read File Record";
        case 21: return "Write File Record";
        case 22: return "Mask Write Register";
        case 23: return "Read/Write Multiple Registers";
        case 24: return "Read FIFO Queue";
        case 43: return "Encapsulated Interface Transport";
        default: return "User-Defined";
    }
}

const char *dnp3FunctionCodeName(uint8_t fc) {
    switch (fc) {
        case 0: return "Confirm";
        case 1: return "Read";
        case 2: return "Write";
        case 3: return "Select";
        case 4: return "Operate";
        case 5: return "Direct Operate";
        case 6: return "Direct Operate - No Ack";
        case 7: return "Immediate Freeze";
        case 13: return "Cold Restart";
        case 14: return "Warm Restart";
        case 18: return "Stop Application";
        case 20: return "Enable Unsolicited";
        case 21: return "Disable Unsolicited";
        case 129: return "Response";
        case 130: return "Unsolicited Response";
        default: return nullptr;
    }
}

} // namespace

StreamFrame frameModbus(const char *data, size_t length) {
    if (length < 6) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // Protocol ID must be 0 for Modbus/TCP
    uint16_t protoId = (static_cast<uint16_t>(bytes[2]) << 8) | static_cast<uint16_t>(bytes[3]);
    if (protoId != 0) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    uint16_t pduLen = (static_cast<uint16_t>(bytes[4]) << 8) | static_cast<uint16_t>(bytes[5]);
    if (pduLen < 1 || pduLen > 260) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    size_t total = 6 + pduLen;
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectModbus(Context &ctx, const char *data, size_t length) {
    if (!data || length < 7) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint16_t transId = r.u16_be();
    uint16_t protoId = r.u16_be();
    uint16_t pduLen = r.u16_be();
    uint8_t unitId = r.u8();

    if (protoId != 0) return;

    ctx.pack.protocol = "Modbus";

    if (r.remaining() == 0) return;
    uint8_t fn = r.u8();
    bool isException = (fn & 0x80) != 0;
    const char *fnName = modbusFunctionName(fn);

    std::string summary = std::string(fnName) + " (TransID " + std::to_string(transId) + ", Unit " + std::to_string(unitId) + ")";
    if (isException) {
        summary = "Exception: " + std::string(fnName);
        if (r.remaining() > 0) {
            uint8_t excCode = r.u8();
            summary += " (Code " + std::to_string(excCode) + ")";
            ctx.pack.app_code = excCode;
        }
    }

    ctx.pack.app_type = fn;
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Modbus/TCP", o, 6 + pduLen <= length ? 6 + pduLen : length);
        root.add("Transaction ID: " + std::to_string(transId));
        root.add("Protocol ID: 0 (Modbus/TCP)");
        root.add("Length: " + std::to_string(pduLen));
        root.add("Unit ID: " + std::to_string(unitId));
        root.add("Function Code: " + std::string(fnName) + " (" + std::to_string(fn) + ")");
    }
}

StreamFrame frameDnp3(const char *data, size_t length) {
    if (length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] != 0x05 || bytes[1] != 0x64) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    uint8_t len = bytes[2];
    if (len < 5) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    // DNP3 has 10 bytes link header (including 2 bytes CRC), plus user data blocks of up to 16 bytes followed by 2 bytes CRC
    // Total byte count: 10 + (len - 5) + ((len - 5 + 15) / 16) * 2
    size_t userBytes = len - 5;
    size_t crcBytes = ((userBytes + 15) / 16) * 2;
    size_t total = 10 + userBytes + crcBytes;

    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectDnp3(Context &ctx, const char *data, size_t length) {
    if (!data || length < 10) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] != 0x05 || bytes[1] != 0x64) return;

    ByteReader r(bytes, length);
    r.skip(2); // start 0x05 0x64
    uint8_t dnpLen = r.u8();
    uint8_t ctrl = r.u8();
    uint16_t dest = r.u16_le();
    uint16_t src = r.u16_le();
    uint16_t linkCrc = r.u16_le();
    (void)linkCrc;

    ctx.pack.protocol = "DNP3";
    ctx.pack.source = std::to_string(src);
    ctx.pack.destination = std::to_string(dest);

    std::string summary = "DNP3 (Src " + std::to_string(src) + " -> Dst " + std::to_string(dest) + ")";

    // Check transport / application layer if present
    if (length >= 12 && dnpLen > 5) {
        uint8_t transportHdr = bytes[10];
        (void)transportHdr;
        if (length >= 13) {
            uint8_t appCtrl = bytes[11];
            uint8_t appFc = bytes[12];
            (void)appCtrl;
            const char *fcName = dnp3FunctionCodeName(appFc);
            if (fcName) {
                summary += ", " + std::string(fcName);
                ctx.pack.app_type = appFc;
            }
        }
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Distributed Network Protocol 3.0 (DNP3)", o, length);
        root.add("Length: " + std::to_string(dnpLen));
        root.add("Control: 0x" + hexString(ctrl, 2));
        root.add("Destination: " + std::to_string(dest));
        root.add("Source: " + std::to_string(src));
    }
}

void dissectSocketCan(Context &ctx, const char *data, size_t length) {
    // SocketCAN frame structure (can_frame):
    // can_id (4 bytes, uint32)
    // can_dlc (1 byte)
    // __pad, __res0, len8_dlc (3 bytes)
    // data (8 bytes)
    if (!data || length < 16) {
        ctx.markMalformed("Truncated CAN frame");
        ctx.pack.protocol = "CAN";
        ctx.pack.info = "CAN [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint32_t canIdRaw = r.u32_be();
    uint8_t dlc = r.u8();
    r.skip(3); // padding

    bool isEff = (canIdRaw & 0x80000000U) != 0; // Extended frame format (29-bit)
    bool isRtr = (canIdRaw & 0x40000000U) != 0; // Remote transmission request
    bool isErr = (canIdRaw & 0x20000000U) != 0; // Error message frame

    uint32_t canId = isEff ? (canIdRaw & 0x1FFFFFFFU) : (canIdRaw & 0x000007FFU);

    ctx.pack.protocol = "CAN";
    ctx.pack.app_type = static_cast<uint16_t>(canId & 0xFFFF);

    std::string summary = "CAN ID: " + hexString(canId, isEff ? 8 : 3) + " DLC: " + std::to_string(dlc);
    if (isRtr) summary += " [RTR]";
    if (isErr) summary += " [ERROR]";

    if (dlc > 0 && dlc <= 8 && length >= 8 + dlc) {
        summary += " Data: " + hexString(bytes[8], 2);
        for (size_t i = 1; i < dlc; ++i) {
            summary += " " + hexString(bytes[8 + i], 2).substr(2); // hex byte
        }
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Controller Area Network (CAN)", o, 16);
        root.add("CAN ID: 0x" + hexString(canId, isEff ? 8 : 3) + (isEff ? " (Extended 29-bit)" : " (Standard 11-bit)"));
        root.add("DLC: " + std::to_string(dlc));
        root.add("Remote Transmission Request (RTR): " + std::string(isRtr ? "Yes" : "No"));
        root.add("Error Frame: " + std::string(isErr ? "Yes" : "No"));
    }
}

} // namespace dissect

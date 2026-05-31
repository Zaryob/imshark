#include "industrial.h"
#include "checksum.h"
#include "reader.h"
#include "util.h"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

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
    if (!data || length < 7) return;   // MBAP header

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint16_t transId = r.u16_be();
    uint16_t protoId = r.u16_be();
    uint16_t pduLen = r.u16_be();
    uint8_t unitId = r.u8();

    if (protoId != 0) return;

    ctx.pack.protocol = "Modbus";

    // pduLen counts the unit id and the PDU: it has to cover at least the function code and must not promise more than is there
    if (r.remaining() == 0) {
        ctx.markMalformed("Modbus message without a function code");
        return;
    }
    const bool badLength = pduLen < 2 || size_t(pduLen) - 1 > length - 7;
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
        auto &root = ctx.addLayer("Modbus/TCP", o, std::min<size_t>(length, size_t(6) + pduLen));
        root.add("Transaction ID: " + std::to_string(transId), o, 2);
        root.add("Protocol ID: 0 (Modbus/TCP)", o + 2, 2);
        root.add("Length: " + std::to_string(pduLen), o + 4, 2);
        root.add("Unit ID: " + std::to_string(unitId), o + 6, 1);
        root.add("Function Code: " + std::string(fnName) + " (" + std::to_string(fn) + ")", o + 7, 1);
    }
    if (badLength) ctx.markMalformed("Modbus length field does not match the data");
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

    ctx.pack.protocol = "DNP3";

    // CRC-16/DNP (IEEE 1815): over the first 8 header bytes, and after every block of up to 16 user data bytes
    // (LEN = 5 + user data). A block cut by the end of the capture cannot be decided. The states go to app_flags
    // (bits 0-1 header, bits 2-3 all data blocks: Bad wins over Unverified, which wins over Good) for the filter.
    const uint16_t calcLinkCrc = crc16dnp(data, 8);
    const uint8_t headerState = calcLinkCrc == linkCrc ? kChecksumGood : kChecksumBad;
    struct Block { size_t off, len; uint16_t stored, calc; uint8_t state; };
    std::vector<Block> blocks;
    uint8_t dataState = kChecksumNone;
    if (dnpLen > 5) {
        size_t left = dnpLen - 5, at = 10;
        while (left > 0) {
            Block b{at, std::min<size_t>(left, 16), 0, 0, kChecksumUnverified};
            if (at + b.len + 2 <= length) {
                b.stored = static_cast<uint16_t>(bytes[at + b.len] | (bytes[at + b.len + 1] << 8));
                b.calc = crc16dnp(data + at, b.len);
                b.state = b.stored == b.calc ? kChecksumGood : kChecksumBad;
            }
            auto rank = [](uint8_t st) { return st == kChecksumBad ? 3 : st == kChecksumUnverified ? 2 : st == kChecksumGood ? 1 : 0; };
            if (rank(b.state) > rank(dataState)) dataState = b.state;
            blocks.push_back(b);
            at += b.len + 2;
            left -= b.len;
        }
    }
    ctx.pack.app_flags = static_cast<uint16_t>(headerState | (dataState << 2));
    const bool crcBad = headerState == kChecksumBad || dataState == kChecksumBad;

    std::string summary = "DNP3 (Src " + std::to_string(src) + " -> Dst " + std::to_string(dest) + ")";

    // Transport header, application control and function code are the first three user data bytes (LEN = 5 + user data)
    if (dnpLen >= 8 && length >= 13) {
        const uint8_t appFc = bytes[12];
        const char *fcName = dnp3FunctionCodeName(appFc);
        if (fcName) {
            summary += ", " + std::string(fcName);
            ctx.pack.app_type = appFc;
        }
    }

    if (crcBad) summary += " [Bad CRC]";
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Distributed Network Protocol 3.0 (DNP3)", o, length);
        root.add("Start: 0x0564", o, 2);
        root.add("Length: " + std::to_string(dnpLen), o + 2, 1);
        root.add("Control: " + hexString(ctrl, 2), o + 3, 1);
        root.add("Destination: " + std::to_string(dest), o + 4, 2);
        root.add("Source: " + std::to_string(src), o + 6, 2);
        auto &hc = root.add("Header CRC: " + hexString(linkCrc, 4) + (headerState == kChecksumGood ? " [correct]" : " [incorrect, should be " + hexString(calcLinkCrc, 4) + "]"), o + 8, 2);
        hc.add(std::string("[Checksum Status: ") + checksumStateText(headerState) + "]", o + 8, 2);
        if (headerState == kChecksumBad) hc.add("[Expert Info (Warning/Checksum): bad DNP3 link header CRC-16]", o + 8, 2);
        if (dnpLen >= 8 && length >= 13) {
            root.add("Transport Header: " + hexString(bytes[10], 2), o + 10, 1);
            root.add("Application Control: " + hexString(bytes[11], 2), o + 11, 1);
            root.add("Application Function Code: " + std::to_string(bytes[12]), o + 12, 1);
        }
        for (size_t i = 0; i < blocks.size(); ++i) {
            const Block &b = blocks[i];
            if (b.off >= length) break;
            const size_t shown = std::min(b.len, length - b.off);
            auto &bf = root.add("Data Block " + std::to_string(i + 1) + " (" + std::to_string(b.len) + " bytes)", o + b.off, shown);
            if (b.state == kChecksumUnverified) {
                bf.add("[Checksum Status: Unverified]", o + b.off, shown);
                continue;
            }
            auto &cf = bf.add("Data CRC: " + hexString(b.stored, 4) + (b.state == kChecksumGood ? " [correct]" : " [incorrect, should be " + hexString(b.calc, 4) + "]"), o + b.off + b.len, 2);
            cf.add(std::string("[Checksum Status: ") + checksumStateText(b.state) + "]", o + b.off + b.len, 2);
            if (b.state == kChecksumBad) cf.add("[Expert Info (Warning/Checksum): bad DNP3 data block CRC-16]", o + b.off + b.len, 2);
        }
    }
}

void dissectSocketCan(Context &ctx, const char *data, size_t length) {
    // SocketCAN (LINKTYPE_CAN_SOCKETCAN): can_id and flags (4 bytes, network byte order), length (1 byte), then
    //   classic CAN (16 bytes):  3 bytes padding, 8 data bytes
    //   CAN FD (72 bytes):       flags, 2 reserved bytes, 64 data bytes
    if (!data || length < 16) {
        ctx.pack.protocol = "CAN";
        ctx.markMalformed("Truncated CAN frame");
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    const uint32_t canIdRaw = r.u32_be();
    const uint8_t dlc = r.u8();
    const bool fd = length >= 72;
    const uint8_t fdFlags = bytes[5];

    const bool isEff = (canIdRaw & 0x80000000U) != 0; // Extended frame format (29-bit)
    const bool isRtr = (canIdRaw & 0x40000000U) != 0; // Remote transmission request
    const bool isErr = (canIdRaw & 0x20000000U) != 0; // Error message frame

    const uint32_t canId = isEff ? (canIdRaw & 0x1FFFFFFFU) : (canIdRaw & 0x000007FFU);

    ctx.pack.protocol = fd ? "CAN FD" : "CAN";
    ctx.pack.app_type = static_cast<uint16_t>(canId & 0xFFFF);
    ctx.pack.app_code = static_cast<uint16_t>(canId >> 16);   // the high bits of a 29-bit identifier

    const size_t maxData = fd ? 64 : 8;
    const size_t dataLen = std::min<size_t>(dlc, maxData);
    const size_t dataAt = 8;
    const size_t shownData = isRtr ? 0 : std::min(dataLen, length - dataAt);

    std::string summary = "CAN ID: " + hexString(canId, isEff ? 8 : 3) + " DLC: " + std::to_string(dlc);
    if (isRtr) summary += " [RTR]";
    if (isErr) summary += " [ERROR]";
    if (shownData > 0) {
        static const char *digits = "0123456789abcdef";
        summary += " Data:";
        for (size_t i = 0; i < shownData && i < 16; ++i) {
            summary += ' ';
            summary += digits[bytes[dataAt + i] >> 4];
            summary += digits[bytes[dataAt + i] & 15];
        }
        if (shownData > 16) summary += " ...";
    }
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer(fd ? "Controller Area Network FD (CAN FD)" : "Controller Area Network (CAN)", o, std::min<size_t>(length, dataAt + shownData));
        root.add("CAN ID: " + hexString(canId, isEff ? 8 : 3) + (isEff ? " (Extended 29-bit)" : " (Standard 11-bit)"), o, 4);
        root.add("DLC: " + std::to_string(dlc), o + 4, 1);
        root.add("Remote Transmission Request (RTR): " + std::string(isRtr ? "Yes" : "No"), o, 4);
        root.add("Error Frame: " + std::string(isErr ? "Yes" : "No"), o, 4);
        if (fd) root.add("FD Flags: " + hexString(fdFlags, 2), o + 5, 1);
        if (shownData > 0) root.add("Data (" + std::to_string(shownData) + " bytes)", o + dataAt, shownData);
    }
}

} // namespace dissect

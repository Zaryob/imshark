#include "protocols.h"

#include "reader.h"
#include "session.h"
#include "util.h"

#include <string>
#include <vector>

namespace dissect {

namespace {

const char *opcodeName(uint16_t op) {
    switch (op) {
        case 1: return "Read Request (RRQ)";
        case 2: return "Write Request (WRQ)";
        case 3: return "Data Packet (DATA)";
        case 4: return "Acknowledgement (ACK)";
        case 5: return "Error Code (ERROR)";
        case 6: return "Option Acknowledgement (OACK)";
        default: return "Unknown Opcode";
    }
}

const char *errorName(uint16_t code) {
    switch (code) {
        case 0: return "Not defined, see error message";
        case 1: return "File not found";
        case 2: return "Access violation";
        case 3: return "Disk full or allocation exceeded";
        case 4: return "Illegal TFTP operation";
        case 5: return "Unknown transfer ID";
        case 6: return "File already exists";
        case 7: return "No such user";
        default: return "Unknown error code";
    }
}

} // namespace

void dissectTftp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "TFTP";
    if (length < 2) {
        ctx.markMalformed("TFTP packet shorter than 2-byte opcode");
        return;
    }

    const uint16_t opcode = be16(data);
    ctx.pack.app_type = opcode;
    const size_t baseOffset = ctx.offsetOf(data);

    packet::Field *layer = nullptr;
    if (ctx.wantFields()) {
        layer = &ctx.addLayer(std::string("Trivial File Transfer Protocol (") + opcodeName(opcode) + ")", baseOffset, length);
        layer->add(std::string("Opcode: ") + opcodeName(opcode) + " (" + std::to_string(opcode) + ")", baseOffset, 2);
    }

    ByteReader reader(data + 2, length - 2);

    if (opcode == 1 || opcode == 2) { // RRQ / WRQ
        const size_t fnPos = reader.pos();
        std::string filename = reader.stringZ();
        const size_t fnLen = reader.pos() - fnPos;

        const size_t modePos = reader.pos();
        std::string mode = reader.stringZ();
        const size_t modeLen = reader.pos() - modePos;

        ctx.pack.app_text = filename;
        ctx.pack.app_text2 = mode;

        if (opcode == 1) {
            ctx.pack.info = "Read Request, File: " + filename + ", Mode: " + mode;
        } else {
            ctx.pack.info = "Write Request, File: " + filename + ", Mode: " + mode;
        }

        // Register session if on standard port 69
        if (ctx.sessions && (ctx.pack.dst_port == 69 || ctx.pack.src_port == 69)) {
            const uint16_t clientPort = (ctx.pack.dst_port == 69) ? ctx.pack.src_port : ctx.pack.dst_port;
            const std::string clientIp = (ctx.pack.dst_port == 69) ? ctx.pack.source : ctx.pack.destination;
            const std::string serverIp = (ctx.pack.dst_port == 69) ? ctx.pack.destination : ctx.pack.source;
            ctx.sessions->tftpSessions.push_back({clientIp, clientPort, serverIp, 0});
        }

        if (layer) {
            const size_t fnOff = baseOffset + 2 + fnPos;
            layer->add("Source File: " + filename, fnOff, fnLen);

            const size_t modeOff = baseOffset + 2 + modePos;
            layer->add("Type: " + mode, modeOff, modeLen);

            // Read options (RFC 2347)
            while (reader.remaining() > 0 && reader.ok()) {
                const size_t optStart = baseOffset + 2 + reader.pos();
                std::string optName = reader.stringZ();
                if (optName.empty()) break;
                std::string optVal = reader.stringZ();
                const size_t optLen = (baseOffset + 2 + reader.pos()) - optStart;
                layer->add("Option: " + optName + " = " + optVal, optStart, optLen);
            }
        }
    } else if (opcode == 3) { // DATA
        if (reader.remaining() < 2) {
            ctx.markMalformed("TFTP DATA missing block number");
            return;
        }
        const uint16_t block = reader.u16();
        ctx.pack.app_code = block;
        const size_t dataLen = reader.remaining();
        ctx.pack.info = "Data Packet, Block: " + std::to_string(block);
        if (dataLen > 0) ctx.pack.info += " (" + std::to_string(dataLen) + " bytes)";

        if (layer) {
            layer->add("Block: " + std::to_string(block), baseOffset + 2, 2);
            if (dataLen > 0) {
                layer->add("Data (" + std::to_string(dataLen) + " bytes): " + asciiPreview(data + 4, dataLen),
                           baseOffset + 4, dataLen);
            }
        }
    } else if (opcode == 4) { // ACK
        if (reader.remaining() < 2) {
            ctx.markMalformed("TFTP ACK missing block number");
            return;
        }
        const uint16_t block = reader.u16();
        ctx.pack.app_code = block;
        ctx.pack.info = "Acknowledgement, Block: " + std::to_string(block);

        if (layer) {
            layer->add("Block: " + std::to_string(block), baseOffset + 2, 2);
        }
    } else if (opcode == 5) { // ERROR
        if (reader.remaining() < 2) {
            ctx.markMalformed("TFTP ERROR missing error code");
            return;
        }
        const uint16_t errCode = reader.u16();
        const size_t msgStart = reader.pos();
        std::string errMsg = reader.stringZ();
        const size_t msgLen = reader.pos() - msgStart;
        ctx.pack.app_code = errCode;
        ctx.pack.app_text = errMsg;
        ctx.pack.info = "Error Code, Code: " + std::to_string(errCode) + ", Message: " + errMsg;

        if (layer) {
            layer->add("Error Code: " + std::string(errorName(errCode)) + " (" + std::to_string(errCode) + ")", baseOffset + 2, 2);
            layer->add("Error Message: " + errMsg, baseOffset + 2 + msgStart, msgLen);
        }
    } else if (opcode == 6) { // OACK
        ctx.pack.info = "Option Acknowledgement";
        std::string optSummary;
        while (reader.remaining() > 0 && reader.ok()) {
            const size_t optStart = baseOffset + 2 + reader.pos();
            std::string optName = reader.stringZ();
            if (optName.empty()) break;
            std::string optVal = reader.stringZ();
            const size_t optLen = (baseOffset + 2 + reader.pos()) - optStart;
            if (!optSummary.empty()) optSummary += ", ";
            optSummary += optName + "=" + optVal;
            if (layer) {
                layer->add("Option: " + optName + " = " + optVal, optStart, optLen);
            }
        }
        if (!optSummary.empty()) {
            ctx.pack.info += " (" + optSummary + ")";
            ctx.pack.app_text2 = optSummary;
        }
    } else {
        ctx.pack.info = "Unknown Opcode (" + std::to_string(opcode) + ")";
    }
}

} // namespace dissect

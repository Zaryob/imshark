#include "protocols.h"

#include "reader.h"
#include "util.h"

#include <algorithm>
#include <string>
#include <vector>

namespace dissect {

namespace {

const char *commandName(uint8_t cmd) {
    switch (cmd) {
        case 240: return "Subnegotiation End (SE)";
        case 241: return "No Operation (NOP)";
        case 242: return "Data Mark (DM)";
        case 243: return "Break (BRK)";
        case 244: return "Interrupt Process (IP)";
        case 245: return "Abort Output (AO)";
        case 246: return "Are You There (AYT)";
        case 247: return "Erase Character (EC)";
        case 248: return "Erase Line (EL)";
        case 249: return "Go Ahead (GA)";
        case 250: return "Subnegotiation (SB)";
        case 251: return "Will";
        case 252: return "Won't";
        case 253: return "Do";
        case 254: return "Don't";
        case 255: return "Interpret as Command (IAC)";
        default: return "Unknown Command";
    }
}

const char *optionName(uint8_t opt) {
    switch (opt) {
        case 0: return "Binary Transmission";
        case 1: return "Echo";
        case 2: return "Reconnection";
        case 3: return "Suppress Go Ahead";
        case 4: return "Approx Message Size Negotiation";
        case 5: return "Status";
        case 6: return "Timing Mark";
        case 7: return "Remote Controlled Trans and Echo";
        case 8: return "Output Line Width";
        case 9: return "Output Page Size";
        case 10: return "Output Carriage-Return Disposition";
        case 11: return "Output Horizontal Tab Stops";
        case 12: return "Output Horizontal Tab Disposition";
        case 13: return "Output Formfeed Disposition";
        case 14: return "Output Vertical Tab Stops";
        case 15: return "Output Vertical Tab Disposition";
        case 16: return "Output Linefeed Disposition";
        case 17: return "Extended ASCII";
        case 18: return "Logout";
        case 19: return "Byte Macro";
        case 20: return "Data Entry Terminal";
        case 21: return "SUPDUP";
        case 22: return "SUPDUP Output";
        case 23: return "Send Location";
        case 24: return "Terminal Type";
        case 25: return "End of Record";
        case 26: return "TACACS User Identification";
        case 27: return "Output Marking";
        case 28: return "Terminal Location Number";
        case 29: return "Telnet 3270 Regime";
        case 30: return "X.3 PAD";
        case 31: return "Negotiate About Window Size (NAWS)";
        case 32: return "Terminal Speed";
        case 33: return "Remote Flow Control";
        case 34: return "Linemode";
        case 35: return "X Display Location";
        case 36: return "Environment Option";
        case 37: return "Authentication Option";
        case 38: return "Encryption Option";
        case 39: return "New Environment Option";
        case 40: return "TN3270E";
        case 42: return "CHARSET";
        case 44: return "Com Port Control";
        case 47: return "KERMIT";
        default: return "Unknown Option";
    }
}

} // namespace

void dissectTelnet(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "Telnet";
    if (length == 0) return;

    packet::Field *layer = nullptr;
    const size_t baseOffset = ctx.offsetOf(data);
    if (ctx.wantFields()) {
        layer = &ctx.addLayer("Telnet", baseOffset, length);
    }

    size_t i = 0;
    std::vector<std::string> summaries;
    uint8_t firstCmd = 0;
    uint8_t firstOpt = 0;
    std::string textPreview;
    bool hasCommands = false;

    while (i < length) {
        if (static_cast<uint8_t>(data[i]) == 255) { // IAC
            hasCommands = true;
            if (i + 1 >= length) {
                // Truncated IAC at end of segment
                if (layer) {
                    layer->add("Interpret as Command (IAC) [truncated]", baseOffset + i, 1);
                }
                summaries.push_back("IAC [truncated]");
                break;
            }

            const uint8_t cmd = static_cast<uint8_t>(data[i + 1]);
            if (cmd == 255) {
                // Escaped literal 0xFF
                if (layer) {
                    layer->add("Literal Data: 0xFF", baseOffset + i, 2);
                }
                i += 2;
                continue;
            }

            if (firstCmd == 0) firstCmd = cmd;

            if (cmd == 251 || cmd == 252 || cmd == 253 || cmd == 254) {
                // WILL / WONT / DO / DONT: 3 bytes (IAC, cmd, option)
                if (i + 2 >= length) {
                    // Truncated option
                    if (layer) {
                        packet::Field &cmdItem = layer->add(std::string("Command: ") + commandName(cmd) + " (" + std::to_string(cmd) + ") [truncated]",
                                                            baseOffset + i, length - i);
                        cmdItem.add("Interpret as Command (IAC)", baseOffset + i, 1);
                    }
                    summaries.push_back(std::string(commandName(cmd)) + " [truncated]");
                    break;
                }

                const uint8_t opt = static_cast<uint8_t>(data[i + 2]);
                if (firstOpt == 0) firstOpt = opt;

                const std::string optDesc = std::string(optionName(opt)) + " (" + std::to_string(opt) + ")";
                const std::string cmdDesc = std::string(commandName(cmd)) + " " + optionName(opt);
                summaries.push_back(cmdDesc);

                if (layer) {
                    packet::Field &cmdItem = layer->add(cmdDesc, baseOffset + i, 3);
                    cmdItem.add("Interpret as Command (IAC)", baseOffset + i, 1);
                    cmdItem.add(std::string("Command: ") + commandName(cmd) + " (" + std::to_string(cmd) + ")", baseOffset + i + 1, 1);
                    cmdItem.add(std::string("Option: ") + optDesc, baseOffset + i + 2, 1);
                }
                i += 3;
            } else if (cmd == 250) { // SB (Subnegotiation Begin)
                if (i + 2 >= length) {
                    if (layer) {
                        layer->add("Subnegotiation Begin (SB) [truncated]", baseOffset + i, length - i);
                    }
                    summaries.push_back("SB [truncated]");
                    break;
                }

                const uint8_t opt = static_cast<uint8_t>(data[i + 2]);
                if (firstOpt == 0) firstOpt = opt;

                // Search for IAC SE (0xFF 0xF0)
                size_t sePos = std::string::npos;
                for (size_t s = i + 3; s + 1 < length; ++s) {
                    if (static_cast<uint8_t>(data[s]) == 255 && static_cast<uint8_t>(data[s + 1]) == 240) {
                        sePos = s;
                        break;
                    }
                }

                if (sePos == std::string::npos) {
                    // Truncated / unterminated subnegotiation
                    const size_t sbLen = length - i;
                    if (layer) {
                        packet::Field &sbItem = layer->add(std::string("Subnegotiation: ") + optionName(opt) + " [unterminated]",
                                                           baseOffset + i, sbLen);
                        sbItem.add("Interpret as Command (IAC)", baseOffset + i, 1);
                        sbItem.add("Subnegotiation Begin (SB)", baseOffset + i + 1, 1);
                        sbItem.add(std::string("Option: ") + optionName(opt) + " (" + std::to_string(opt) + ")", baseOffset + i + 2, 1);
                    }
                    summaries.push_back(std::string("SB ") + optionName(opt) + " [unterminated]");
                    break;
                }

                const size_t totalSbLen = (sePos + 2) - i;
                const size_t paramLen = sePos - (i + 3);
                const char *params = data + i + 3;

                std::string sbDetail;
                if (opt == 31 && paramLen == 4) { // NAWS: 16-bit width, 16-bit height
                    const uint16_t w = be16(params);
                    const uint16_t h = be16(params + 2);
                    sbDetail = "Width: " + std::to_string(w) + ", Height: " + std::to_string(h);
                } else if ((opt == 24 || opt == 32) && paramLen >= 1) { // Terminal Type (24) / Speed (32)
                    const uint8_t subcmd = static_cast<uint8_t>(params[0]);
                    const std::string modeStr = (subcmd == 1 ? "SEND" : (subcmd == 0 ? "IS" : std::to_string(subcmd)));
                    std::string val(params + 1, paramLen - 1);
                    sbDetail = modeStr + (val.empty() ? "" : (" " + val));
                } else if (paramLen > 0) {
                    sbDetail = asciiPreview(params, paramLen, 30);
                }

                std::string sbTitle = std::string("Subnegotiation: ") + optionName(opt);
                if (!sbDetail.empty()) sbTitle += " (" + sbDetail + ")";
                summaries.push_back(std::string("SB ") + optionName(opt) + (sbDetail.empty() ? "" : (" " + sbDetail)));

                if (layer) {
                    packet::Field &sbItem = layer->add(sbTitle, baseOffset + i, totalSbLen);
                    sbItem.add("Interpret as Command (IAC)", baseOffset + i, 1);
                    sbItem.add("Subnegotiation Begin (SB)", baseOffset + i + 1, 1);
                    sbItem.add(std::string("Option: ") + optionName(opt) + " (" + std::to_string(opt) + ")", baseOffset + i + 2, 1);
                    if (opt == 31 && paramLen == 4) {
                        const uint16_t w = be16(params);
                        const uint16_t h = be16(params + 2);
                        sbItem.add("Width: " + std::to_string(w), baseOffset + i + 3, 2);
                        sbItem.add("Height: " + std::to_string(h), baseOffset + i + 5, 2);
                    } else if (paramLen > 0) {
                        sbItem.add("Subnegotiation Data: " + asciiPreview(params, paramLen), baseOffset + i + 3, paramLen);
                    }
                    sbItem.add("Interpret as Command (IAC)", baseOffset + sePos, 1);
                    sbItem.add("Subnegotiation End (SE)", baseOffset + sePos + 1, 1);
                }
                i = sePos + 2;
            } else {
                // 2-byte command (NOP, AYT, DM, etc.)
                const std::string cmdDesc = std::string("Command: ") + commandName(cmd) + " (" + std::to_string(cmd) + ")";
                summaries.push_back(commandName(cmd));
                if (layer) {
                    packet::Field &cmdItem = layer->add(cmdDesc, baseOffset + i, 2);
                    cmdItem.add("Interpret as Command (IAC)", baseOffset + i, 1);
                    cmdItem.add(cmdDesc, baseOffset + i + 1, 1);
                }
                i += 2;
            }
        } else {
            // Text data chunk
            size_t nextIac = i + 1;
            while (nextIac < length && static_cast<uint8_t>(data[nextIac]) != 255) {
                ++nextIac;
            }
            const size_t textLen = nextIac - i;
            const std::string preview = asciiPreview(data + i, textLen);
            if (textPreview.empty()) {
                textPreview = std::string(data + i, std::min<size_t>(textLen, 50));
            }
            if (layer) {
                layer->add("Data (" + std::to_string(textLen) + " bytes): " + preview, baseOffset + i, textLen);
            }
            i = nextIac;
        }
    }

    ctx.pack.app_type = firstCmd;
    ctx.pack.app_code = firstOpt;

    if (!hasCommands) {
        // Plain text data
        ctx.pack.info += "[ Telnet data: " + textPreview + (length > 50 ? "..." : "") + " ]";
        ctx.pack.app_text = textPreview;
    } else {
        std::string summary;
        for (size_t s = 0; s < summaries.size(); ++s) {
            if (s > 0) summary += ", ";
            summary += summaries[s];
            if (summary.size() > 80 && s + 1 < summaries.size()) {
                summary += "...";
                break;
            }
        }
        ctx.pack.info += "[ Telnet: " + summary + " ]";
        ctx.pack.app_text = summary;
    }
}

} // namespace dissect

#include "protocols.h"

#include "reader.h"
#include "session.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>
#include <vector>

namespace dissect {

namespace {

std::string trimCrlf(const std::string &s) {
    size_t end = s.size();
    while (end > 0 && (s[end - 1] == '\r' || s[end - 1] == '\n')) {
        --end;
    }
    return s.substr(0, end);
}

bool parsePortNumbers(const std::string &str, std::string &ip, uint16_t &port) {
    std::vector<int> nums;
    size_t start = 0;
    while (start < str.size()) {
        while (start < str.size() && !std::isdigit(static_cast<unsigned char>(str[start]))) ++start;
        if (start >= str.size()) break;
        size_t end = start;
        while (end < str.size() && std::isdigit(static_cast<unsigned char>(str[end]))) ++end;
        int val = 0;
        std::from_chars(str.data() + start, str.data() + end, val);
        nums.push_back(val);
        start = end;
    }
    if (nums.size() >= 6) {
        ip = std::to_string(nums[0]) + "." + std::to_string(nums[1]) + "." +
             std::to_string(nums[2]) + "." + std::to_string(nums[3]);
        port = static_cast<uint16_t>((nums[4] << 8) | (nums[5] & 0xFF));
        return true;
    }
    return false;
}

bool parsePasvResponse(const std::string &line, std::string &ip, uint16_t &port) {
    const size_t openParen = line.find('(');
    const size_t closeParen = line.find(')', openParen == std::string::npos ? 0 : openParen);
    if (openParen != std::string::npos && closeParen != std::string::npos && closeParen > openParen + 1) {
        return parsePortNumbers(line.substr(openParen + 1, closeParen - openParen - 1), ip, port);
    }
    return parsePortNumbers(line, ip, port);
}

bool parseEpsvResponse(const std::string &line, uint16_t &port) {
    // Format: (|||port|) or |1|ip|port|
    const size_t openParen = line.find('(');
    const size_t closeParen = line.find(')', openParen == std::string::npos ? 0 : openParen);
    std::string inner = (openParen != std::string::npos && closeParen != std::string::npos && closeParen > openParen)
                            ? line.substr(openParen + 1, closeParen - openParen - 1)
                            : line;
    if (inner.size() >= 5) {
        const char delim = inner[0];
        if (inner[1] == delim && inner[2] == delim) {
            size_t pEnd = inner.find(delim, 3);
            if (pEnd != std::string::npos && pEnd > 3) {
                int p = 0;
                std::from_chars(inner.data() + 3, inner.data() + pEnd, p);
                if (p > 0 && p <= 65535) {
                    port = static_cast<uint16_t>(p);
                    return true;
                }
            }
        }
    }
    return false;
}

bool parseEprtCommand(const std::string &arg, std::string &ip, uint16_t &port) {
    // Format: |proto|addr|port|
    if (arg.size() < 7) return false;
    const char delim = arg[0];
    size_t p1 = arg.find(delim, 1);
    if (p1 == std::string::npos) return false;
    size_t p2 = arg.find(delim, p1 + 1);
    if (p2 == std::string::npos) return false;
    size_t p3 = arg.find(delim, p2 + 1);
    if (p3 == std::string::npos) return false;

    ip = arg.substr(p1 + 1, p2 - p1 - 1);
    int p = 0;
    std::from_chars(arg.data() + p2 + 1, arg.data() + p3, p);
    if (p > 0 && p <= 65535) {
        port = static_cast<uint16_t>(p);
        return true;
    }
    return false;
}

} // namespace

void dissectFtp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "FTP";
    if (length == 0) return;

    packet::Field *layer = nullptr;
    const size_t baseOffset = ctx.offsetOf(data);
    if (ctx.wantFields()) {
        layer = &ctx.addLayer("File Transfer Protocol (FTP)", baseOffset, length);
    }

    size_t lineStart = 0;
    std::vector<std::pair<size_t, size_t>> lines; // [start, len]
    while (lineStart < length) {
        size_t lineEnd = lineStart;
        while (lineEnd < length && data[lineEnd] != '\n') {
            ++lineEnd;
        }
        if (lineEnd < length && data[lineEnd] == '\n') {
            ++lineEnd;
        }
        lines.emplace_back(lineStart, lineEnd - lineStart);
        lineStart = lineEnd;
    }

    uint8_t firstType = 0;     // 1 = request/command, 2 = response
    uint32_t firstCode = 0;
    std::string firstCmd;
    std::string firstArg;
    std::string firstLineTrimmed;

    for (const auto &[lStart, lLen] : lines) {
        std::string rawLine(data + lStart, lLen);
        std::string line = trimCrlf(rawLine);
        if (line.empty()) continue;

        if (firstLineTrimmed.empty()) {
            firstLineTrimmed = line;
        }

        bool isResponse = false;
        if (line.size() >= 3 && std::isdigit(static_cast<unsigned char>(line[0])) &&
            std::isdigit(static_cast<unsigned char>(line[1])) &&
            std::isdigit(static_cast<unsigned char>(line[2]))) {
            if (line.size() == 3 || line[3] == ' ' || line[3] == '-') {
                isResponse = true;
            }
        }

        if (isResponse) {
            const uint32_t code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
            const bool more = (line.size() > 3 && line[3] == '-');
            std::string param = (line.size() > 4 ? line.substr(4) : "");

            if (firstType == 0) {
                firstType = 2; // response
                firstCode = code;
                firstCmd = std::to_string(code);
                firstArg = param;
            }

            std::string pasvIp;
            uint16_t pasvPort = 0;
            bool hasPasvPort = false;
            if (code == 227) {
                hasPasvPort = parsePasvResponse(param, pasvIp, pasvPort);
            } else if (code == 229) {
                hasPasvPort = parseEpsvResponse(param, pasvPort);
            }
            if (hasPasvPort && pasvPort != 0 && ctx.sessions) {
                ctx.sessions->ftpDataPorts.insert(pasvPort);
            }

            if (layer) {
                packet::Field &respItem = layer->add("Response: " + line, baseOffset + lStart, lLen);
                respItem.add("Response code: " + std::to_string(code), baseOffset + lStart, 3);
                if (line.size() > 3) {
                    respItem.add(std::string("Response continuation: ") + (more ? "more lines to follow (-)" : "end of response ( )"),
                                 baseOffset + lStart + 3, 1);
                }
                if (!param.empty()) {
                    respItem.add("Response parameter: " + param, baseOffset + lStart + 4, param.size());
                }
                if (hasPasvPort) {
                    if (code == 229) {
                        respItem.add("Extended passive port: " + std::to_string(pasvPort));
                    } else {
                        if (!pasvIp.empty()) respItem.add("Passive IPv4 address: " + pasvIp);
                        respItem.add("Passive port: " + std::to_string(pasvPort));
                    }
                }
            }
        } else {
            // FTP command
            std::string cmd;
            std::string arg;
            const size_t sp = line.find(' ');
            if (sp != std::string::npos) {
                cmd = line.substr(0, sp);
                size_t aStart = sp + 1;
                while (aStart < line.size() && line[aStart] == ' ') ++aStart;
                arg = line.substr(aStart);
            } else {
                cmd = line;
            }

            std::string upperCmd = cmd;
            for (char &c : upperCmd) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

            if (firstType == 0) {
                firstType = 1; // request
                firstCmd = upperCmd;
                firstArg = arg;
            }

            std::string actIp;
            uint16_t actPort = 0;
            bool hasActPort = false;
            if (upperCmd == "PORT") {
                hasActPort = parsePortNumbers(arg, actIp, actPort);
            } else if (upperCmd == "EPRT") {
                hasActPort = parseEprtCommand(arg, actIp, actPort);
            }
            if (hasActPort && actPort != 0 && ctx.sessions) {
                ctx.sessions->ftpDataPorts.insert(actPort);
            }

            if (layer) {
                packet::Field &cmdItem = layer->add("Command: " + line, baseOffset + lStart, lLen);
                cmdItem.add("Command name: " + upperCmd, baseOffset + lStart, cmd.size());
                if (!arg.empty()) {
                    cmdItem.add("Command parameter: " + arg, baseOffset + lStart + (line.size() - arg.size()), arg.size());
                }
                if (hasActPort) {
                    if (!actIp.empty()) cmdItem.add("Active address: " + actIp);
                    cmdItem.add("Active port: " + std::to_string(actPort));
                }
            }
        }
    }

    ctx.pack.app_type = firstType;
    ctx.pack.app_code = firstCode;
    ctx.pack.app_text = firstCmd;
    ctx.pack.app_text2 = firstArg;

    if (firstLineTrimmed.size() > 50) {
        firstLineTrimmed = firstLineTrimmed.substr(0, 50) + "...";
    }

    if (firstType == 1) {
        ctx.pack.info = "Request: " + firstLineTrimmed;
    } else if (firstType == 2) {
        ctx.pack.info = "Response: " + firstLineTrimmed;
    } else {
        ctx.pack.info = "FTP: " + firstLineTrimmed;
    }
}

void dissectFtpData(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "FTP-DATA";
    const std::string preview = asciiPreview(data, length);
    ctx.pack.info = "FTP Data: " + preview + " (" + std::to_string(length) + " bytes)";
    ctx.pack.app_type = 3;
    ctx.pack.app_code = static_cast<uint32_t>(length);
    ctx.pack.app_text = preview;

    if (ctx.wantFields() && length > 0) {
        const size_t baseOffset = ctx.offsetOf(data);
        packet::Field &layer = ctx.addLayer("FTP Data", baseOffset, length);
        layer.add("Data (" + std::to_string(length) + " bytes): " + preview, baseOffset, length);
    }
}

} // namespace dissect

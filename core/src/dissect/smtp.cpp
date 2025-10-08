#include "protocols.h"

#include "reader.h"
#include "util.h"

#include <algorithm>
#include <cctype>
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

std::string extractAddress(const std::string &s) {
    const size_t start = s.find('<');
    const size_t end = s.find('>', start == std::string::npos ? 0 : start);
    if (start != std::string::npos && end != std::string::npos && end > start + 1) {
        return s.substr(start + 1, end - start - 1);
    }
    const size_t colon = s.find(':');
    if (colon != std::string::npos && colon + 1 < s.size()) {
        size_t first = colon + 1;
        while (first < s.size() && (s[first] == ' ' || s[first] == '\t')) ++first;
        return trimCrlf(s.substr(first));
    }
    return "";
}

} // namespace

void dissectSmtp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "SMTP";
    if (length == 0) return;

    packet::Field *layer = nullptr;
    const size_t baseOffset = ctx.offsetOf(data);
    if (ctx.wantFields()) {
        layer = &ctx.addLayer("Simple Mail Transfer Protocol", baseOffset, length);
    }

    // Split payload into lines
    size_t lineStart = 0;
    std::vector<std::pair<size_t, size_t>> lines; // [start, len]
    while (lineStart < length) {
        size_t lineEnd = lineStart;
        while (lineEnd < length && data[lineEnd] != '\n') {
            ++lineEnd;
        }
        if (lineEnd < length && data[lineEnd] == '\n') {
            ++lineEnd; // include '\n'
        }
        lines.emplace_back(lineStart, lineEnd - lineStart);
        lineStart = lineEnd;
    }

    uint8_t firstType = 0;     // 1 = command, 2 = response, 3 = data
    uint32_t firstCode = 0;    // 3-digit reply code
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

        // Check if response: 3 digits followed by ' ', '-', or end-of-line
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
            }
        } else {
            // Check for SMTP Commands or Message Data
            std::string upperLine = line;
            for (char &c : upperLine) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

            // Known SMTP commands
            static const char *const COMMANDS[] = {
                "EHLO", "HELO", "MAIL FROM:", "RCPT TO:", "DATA", "RSET", "NOOP",
                "QUIT", "VRFY", "EXPN", "HELP", "STARTTLS", "AUTH", "BDAT", "ATRN"
            };

            std::string matchedCmd;
            for (const char *cmd : COMMANDS) {
                if (upperLine.rfind(cmd, 0) == 0) {
                    matchedCmd = cmd;
                    break;
                }
            }

            if (!matchedCmd.empty()) {
                if (firstType == 0) {
                    firstType = 1; // command
                    firstCmd = matchedCmd;
                }

                std::string arg;
                if (matchedCmd == "MAIL FROM:" || matchedCmd == "RCPT TO:") {
                    arg = extractAddress(line);
                    if (firstArg.empty()) firstArg = arg;
                } else if (line.size() > matchedCmd.size()) {
                    size_t aPos = matchedCmd.size();
                    while (aPos < line.size() && (line[aPos] == ' ' || line[aPos] == '\t')) ++aPos;
                    arg = line.substr(aPos);
                    if (firstArg.empty()) firstArg = arg;
                }

                if (layer) {
                    packet::Field &cmdItem = layer->add("Command: " + line, baseOffset + lStart, lLen);
                    cmdItem.add("Command name: " + matchedCmd, baseOffset + lStart, matchedCmd.size());
                    if (!arg.empty()) {
                        cmdItem.add("Command parameter: " + arg, baseOffset + lStart + (line.size() - arg.size()), arg.size());
                    }
                }
            } else {
                // Header inside DATA (From, To, Subject, Date) or raw data line
                if (firstType == 0) firstType = 3; // data

                if (layer) {
                    if (upperLine.rfind("FROM: ", 0) == 0 || upperLine.rfind("TO: ", 0) == 0 ||
                        upperLine.rfind("SUBJECT: ", 0) == 0 || upperLine.rfind("DATE: ", 0) == 0) {
                        layer->add("Header: " + line, baseOffset + lStart, lLen);
                    } else if (line == ".") {
                        layer->add("End of message data (.)", baseOffset + lStart, lLen);
                    } else {
                        layer->add("Data: " + line, baseOffset + lStart, lLen);
                    }
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

    if (firstType == 1) { // Command
        ctx.pack.info = "C: " + firstLineTrimmed;
    } else if (firstType == 2) { // Response
        ctx.pack.info = "S: " + firstLineTrimmed;
    } else {
        ctx.pack.info = "SMTP data: " + firstLineTrimmed;
    }
}

} // namespace dissect

#include "voip.h"
#include "reader.h"
#include "util.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <string>

namespace dissect {

namespace {

// Checks if a string starts with prefix (case-insensitive)
bool startsWithCi(std::string_view str, std::string_view prefix) {
    if (str.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(str[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

// Finds header value by name
std::string getHeaderValue(const std::string &headers, const std::string &headerName) {
    std::string search = "\n" + headerName + ":";
    std::string text = "\n" + headers;
    auto pos = text.find(search);
    if (pos == std::string::npos) return {};
    pos += search.size();
    while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t')) pos++;
    auto endPos = text.find('\r', pos);
    if (endPos == std::string::npos) endPos = text.find('\n', pos);
    if (endPos == std::string::npos) endPos = text.size();
    return text.substr(pos, endPos - pos);
}

} // namespace

StreamFrame frameSip(const char *data, size_t length) {
    if (length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    std::string_view s(data, length);
    auto hdrEnd = s.find("\r\n\r\n");
    size_t sepLen = 4;
    if (hdrEnd == std::string_view::npos) {
        hdrEnd = s.find("\n\n");
        sepLen = 2;
    }
    if (hdrEnd == std::string_view::npos) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }

    std::string headers(s.substr(0, hdrEnd));
    std::string clStr = getHeaderValue(headers, "Content-Length");
    if (clStr.empty()) clStr = getHeaderValue(headers, "l"); // short form for Content-Length in SIP

    size_t bodyLen = 0;
    if (!clStr.empty()) {
        try {
            bodyLen = std::stoul(clStr);
        } catch (...) {
            bodyLen = 0;
        }
    }

    size_t total = hdrEnd + sepLen + bodyLen;
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectSip(Context &ctx, const char *data, size_t length) {
    if (!data || length < 10) return;

    std::string_view s(data, length);
    auto lineEnd = s.find("\r\n");
    if (lineEnd == std::string_view::npos) lineEnd = s.find('\n');
    if (lineEnd == std::string_view::npos) return;

    std::string firstLine(s.substr(0, lineEnd));
    ctx.pack.protocol = "SIP";

    bool isResponse = startsWithCi(firstLine, "SIP/2.0");
    std::string summary = firstLine;

    // Search headers for Call-ID, CSeq, From, To
    auto hdrEnd = s.find("\r\n\r\n");
    std::string headers;
    if (hdrEnd != std::string_view::npos) {
        headers = std::string(s.substr(0, hdrEnd));
    } else {
        headers = std::string(s);
    }

    std::string callId = getHeaderValue(headers, "Call-ID");
    if (callId.empty()) callId = getHeaderValue(headers, "i");
    std::string cseq = getHeaderValue(headers, "CSeq");

    if (!cseq.empty()) {
        summary = firstLine + " | " + cseq;
    }
    ctx.pack.info = summary;
    ctx.pack.app_text = callId;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer(std::string("Session Initiation Protocol (") + (isResponse ? "Response" : "Request") + ")", o, length);
        root.add(firstLine);
        if (!cseq.empty()) root.add("CSeq: " + cseq);
        if (!callId.empty()) root.add("Call-ID: " + callId);

        std::string from = getHeaderValue(headers, "From");
        if (!from.empty()) root.add("From: " + from);
        std::string to = getHeaderValue(headers, "To");
        if (!to.empty()) root.add("To: " + to);

        // Dissect SDP body if present
        if (hdrEnd != std::string_view::npos && hdrEnd + 4 < length) {
            std::string body(s.substr(hdrEnd + 4));
            if (body.find("v=") != std::string::npos && body.find("m=") != std::string::npos) {
                auto &sdp = ctx.addLayer("Session Description Protocol", o + hdrEnd + 4, body.size());
                std::istringstream stream(body);
                std::string line;
                while (std::getline(stream, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (!line.empty()) sdp.add(line);
                }
            }
        }
    }
}

StreamFrame frameRtsp(const char *data, size_t length) {
    return frameSip(data, length); // RTSP uses exact same HTTP-like Content-Length framing
}

void dissectRtsp(Context &ctx, const char *data, size_t length) {
    if (!data || length < 10) return;

    std::string_view s(data, length);
    auto lineEnd = s.find("\r\n");
    if (lineEnd == std::string_view::npos) lineEnd = s.find('\n');
    if (lineEnd == std::string_view::npos) return;

    std::string firstLine(s.substr(0, lineEnd));
    ctx.pack.protocol = "RTSP";
    ctx.pack.info = firstLine;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Real Time Streaming Protocol", o, length);
        root.add(firstLine);
    }
}

void dissectRtp(Context &ctx, const char *data, size_t length) {
    if (!data || length < 12) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    uint8_t vPXM = bytes[0];
    uint8_t version = (vPXM >> 6) & 0x03;
    if (version != 2) return; // RTP version must be 2

    bool padding = (vPXM & 0x20) != 0;
    bool extension = (vPXM & 0x10) != 0;
    uint8_t csrcCount = vPXM & 0x0F;

    uint8_t mPt = bytes[1];
    bool marker = (mPt & 0x80) != 0;
    uint8_t payloadType = mPt & 0x7F;

    uint16_t seq = (static_cast<uint16_t>(bytes[2]) << 8) | static_cast<uint16_t>(bytes[3]);
    uint32_t timestamp = (static_cast<uint32_t>(bytes[4]) << 24) |
                         (static_cast<uint32_t>(bytes[5]) << 16) |
                         (static_cast<uint32_t>(bytes[6]) << 8) |
                         static_cast<uint32_t>(bytes[7]);
    uint32_t ssrc = (static_cast<uint32_t>(bytes[8]) << 24) |
                    (static_cast<uint32_t>(bytes[9]) << 16) |
                    (static_cast<uint32_t>(bytes[10]) << 8) |
                    static_cast<uint32_t>(bytes[11]);

    ctx.pack.protocol = "RTP";
    ctx.pack.app_type = payloadType;

    std::string summary = "PT=" + std::to_string(payloadType) + ", SSeq=" + std::to_string(seq) +
                          ", TS=" + std::to_string(timestamp) + ", SSRC=0x" + hexString(ssrc, 8);
    if (marker) summary += " [Marker]";

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Real-time Transport Protocol", o, 12 + csrcCount * 4);
        root.add("Version: 2");
        root.add("Padding: " + std::string(padding ? "Yes" : "No"));
        root.add("Extension: " + std::string(extension ? "Yes" : "No"));
        root.add("Marker: " + std::string(marker ? "Yes" : "No"));
        root.add("Payload Type: " + std::to_string(payloadType));
        root.add("Sequence Number: " + std::to_string(seq));
        root.add("Timestamp: " + std::to_string(timestamp));
        root.add("SSRC: 0x" + hexString(ssrc, 8));
    }
}

void dissectRtcp(Context &ctx, const char *data, size_t length) {
    if (!data || length < 8) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    uint8_t vPR = bytes[0];
    uint8_t version = (vPR >> 6) & 0x03;
    if (version != 2) return;

    uint8_t count = vPR & 0x1F;
    uint8_t pt = bytes[1]; // 200 = SR, 201 = RR, 202 = SDES, 203 = BYE, 204 = APP
    uint16_t words = (static_cast<uint16_t>(bytes[2]) << 8) | static_cast<uint16_t>(bytes[3]);
    uint32_t pktLen = (words + 1) * 4;

    uint32_t ssrc = (static_cast<uint32_t>(bytes[4]) << 24) |
                    (static_cast<uint32_t>(bytes[5]) << 16) |
                    (static_cast<uint32_t>(bytes[6]) << 8) |
                    static_cast<uint32_t>(bytes[7]);

    ctx.pack.protocol = "RTCP";
    ctx.pack.app_type = pt;

    const char *ptName = "Unknown";
    switch (pt) {
        case 200: ptName = "Sender Report (SR)"; break;
        case 201: ptName = "Receiver Report (RR)"; break;
        case 202: ptName = "Source Description (SDES)"; break;
        case 203: ptName = "Goodbye (BYE)"; break;
        case 204: ptName = "Application defined (APP)"; break;
        default: break;
    }

    ctx.pack.info = std::string(ptName) + " (SSRC 0x" + hexString(ssrc, 8) + ")";

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("RTP Control Protocol (" + std::string(ptName) + ")", o, pktLen <= length ? pktLen : length);
        root.add("Version: 2");
        root.add("Payload Type: " + std::string(ptName) + " (" + std::to_string(pt) + ")");
        root.add("Report Count: " + std::to_string(count));
        root.add("SSRC: 0x" + hexString(ssrc, 8));
    }
}

} // namespace dissect

#include "voip.h"
#include "reader.h"
#include "util.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace dissect {

namespace {

// Longest message part the stream framers look at, and the biggest body they accept (a SIP/RTSP message that
// claims more is not framed: it would only make a session buffer wait for bytes that never come)
constexpr size_t kMaxHeaderBytes = 64 * 1024;
constexpr size_t kMaxBodyBytes = 64 * 1024;

char lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

bool equalsCi(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

// Checks if a string starts with prefix (case-insensitive)
bool startsWithCi(std::string_view str, std::string_view prefix) {
    return str.size() >= prefix.size() && equalsCi(str.substr(0, prefix.size()), prefix);
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// End of the header block: the earliest blank line (CRLF CRLF or LF LF). `sepLen` is the length of that separator.
bool findHeaderEnd(std::string_view s, size_t &hdrEnd, size_t &sepLen) {
    const auto crlf = s.find("\r\n\r\n");
    const auto lf = s.find("\n\n");
    if (crlf == std::string_view::npos && lf == std::string_view::npos) return false;
    if (lf == std::string_view::npos || (crlf != std::string_view::npos && crlf < lf)) {
        hdrEnd = crlf;
        sepLen = 4;
    } else {
        hdrEnd = lf;
        sepLen = 2;
    }
    return true;
}

// Value of a header (case-insensitive name, optionally also its one-letter compact form, RFC 3261 section 7.3.3).
// The first line of `headers` is the start line and is skipped.
std::string_view headerValue(std::string_view headers, std::string_view name, char compact = 0) {
    size_t pos = headers.find('\n');
    while (pos != std::string_view::npos && pos + 1 <= headers.size()) {
        const size_t begin = pos + 1;
        size_t end = headers.find('\n', begin);
        std::string_view line = headers.substr(begin, end == std::string_view::npos ? std::string_view::npos : end - begin);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            const std::string_view field = trim(line.substr(0, colon));
            if (equalsCi(field, name) || (compact && field.size() == 1 && lower(field[0]) == compact)) {
                return trim(line.substr(colon + 1));
            }
        }
        pos = end;
    }
    return {};
}

// Decimal digits only, at most `cap`; no overflow possible
std::optional<size_t> parseBoundedNumber(std::string_view v, size_t cap) {
    if (v.empty() || v.size() > 9) return std::nullopt;
    size_t n = 0;
    for (char c: v) {
        if (c < '0' || c > '9') return std::nullopt;
        n = n * 10 + static_cast<size_t>(c - '0');
    }
    if (n > cap) return std::nullopt;
    return n;
}

bool isToken(std::string_view s) {
    if (s.empty()) return false;
    for (char c: s) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || std::strchr("-.!%*_+`'~", c))) return false;
    }
    return true;
}

// RFC 3261 section 7.1: Request-Line = Method SP Request-URI SP SIP-Version, Status-Line = SIP-Version SP Status-Code SP Reason.
// `version` is "SIP/2.0" (RTSP: "RTSP/1.0").
bool validStartLine(std::string_view line, std::string_view version) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.size() < version.size() + 4) return false;
    if (startsWithCi(line, version)) { // response: version SP 3 digits [SP reason]
        const auto rest = line.substr(version.size());
        return rest.size() >= 4 && rest[0] == ' ' && std::isdigit(static_cast<unsigned char>(rest[1])) &&
               std::isdigit(static_cast<unsigned char>(rest[2])) && std::isdigit(static_cast<unsigned char>(rest[3])) &&
               (rest.size() == 4 || rest[4] == ' ');
    }
    // request: token SP uri SP version
    const auto first = line.find(' ');
    const auto last = line.rfind(' ');
    if (first == std::string_view::npos || last == first) return false;
    const auto uri = line.substr(first + 1, last - first - 1);
    return isToken(line.substr(0, first)) && !uri.empty() && uri.find(' ') == std::string_view::npos &&
           equalsCi(line.substr(last + 1), version);
}

bool validSipStart(std::string_view line) { return validStartLine(line, "SIP/2.0"); }
bool validRtspStart(std::string_view line) { return validStartLine(line, "RTSP/1.0"); }

// Header-block + Content-Length body framing shared by SIP and RTSP
StreamFrame frameTextMessage(const char *data, size_t length, bool (*validStart)(std::string_view)) {
    std::string_view s(data, std::min(length, kMaxHeaderBytes + 4));
    const auto lineEnd = s.find('\n');
    if (lineEnd == std::string_view::npos) {
        return s.size() >= kMaxHeaderBytes ? StreamFrame{StreamFrame::Kind::Reject, 0} : StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    if (!validStart(s.substr(0, lineEnd))) return StreamFrame{StreamFrame::Kind::Reject, 0};

    size_t hdrEnd = 0, sepLen = 0;
    if (!findHeaderEnd(s, hdrEnd, sepLen)) {
        return s.size() >= kMaxHeaderBytes ? StreamFrame{StreamFrame::Kind::Reject, 0} : StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }

    size_t bodyLen = 0;
    const auto clStr = headerValue(s.substr(0, hdrEnd), "Content-Length", 'l');
    if (!clStr.empty()) {
        const auto cl = parseBoundedNumber(clStr, kMaxBodyBytes);
        if (!cl) return StreamFrame{StreamFrame::Kind::Reject, 0};   // not a number, or more than a message may carry
        bodyLen = *cl;
    }

    const size_t headEnd = hdrEnd + sepLen;
    if (length - std::min(length, headEnd) < bodyLen) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    return StreamFrame{StreamFrame::Kind::Complete, headEnd + bodyLen};
}

std::string_view firstLineOf(std::string_view s) {
    auto lineEnd = s.find("\r\n");
    if (lineEnd == std::string_view::npos) lineEnd = s.find('\n');
    return lineEnd == std::string_view::npos ? std::string_view{} : s.substr(0, lineEnd);
}

std::string shown(std::string_view v) { return printableText(v.data(), v.size()); }

} // namespace

StreamFrame frameSip(const char *data, size_t length) {
    if (length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    return frameTextMessage(data, length, validSipStart);
}

void dissectSip(Context &ctx, const char *data, size_t length) {
    if (!data || length < 10) return;

    std::string_view s(data, length);
    const std::string_view firstLine = firstLineOf(s);
    if (firstLine.empty() || !validSipStart(firstLine)) return;   // some other text on the SIP port: not SIP

    ctx.pack.protocol = "SIP";
    const bool isResponse = startsWithCi(firstLine, "SIP/2.0");

    size_t hdrEnd = 0, sepLen = 0;
    const bool haveBody = findHeaderEnd(s, hdrEnd, sepLen);
    const std::string_view headers = haveBody ? s.substr(0, hdrEnd) : s;

    std::string_view callId = headerValue(headers, "Call-ID", 'i');
    const std::string_view cseq = headerValue(headers, "CSeq");

    std::string summary = shown(firstLine);
    if (!cseq.empty()) summary += " | " + shown(cseq);
    ctx.pack.info = summary;
    ctx.pack.app_text = shown(callId);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer(std::string("Session Initiation Protocol (") + (isResponse ? "Response" : "Request") + ")", o, length);
        root.add(shown(firstLine), o, firstLine.size());
        if (!cseq.empty()) root.add("CSeq: " + shown(cseq));
        if (!callId.empty()) root.add("Call-ID: " + shown(callId));

        const auto from = headerValue(headers, "From", 'f');
        if (!from.empty()) root.add("From: " + shown(from));
        const auto to = headerValue(headers, "To", 't');
        if (!to.empty()) root.add("To: " + shown(to));

        // Dissect SDP body if present
        const size_t bodyStart = haveBody ? hdrEnd + sepLen : length;
        if (bodyStart < length) {
            const std::string_view body = s.substr(bodyStart);
            if (body.rfind("v=", 0) == 0 && body.find("\nm=") != std::string_view::npos) {
                auto &sdp = ctx.addLayer("Session Description Protocol", o + bodyStart, body.size());
                size_t pos = 0;
                while (pos < body.size()) {
                    size_t end = body.find('\n', pos);
                    if (end == std::string_view::npos) end = body.size();
                    const std::string_view line = trim(body.substr(pos, end - pos));
                    if (!line.empty()) sdp.add(shown(line), o + bodyStart + pos, end - pos);
                    pos = end + 1;
                }
            }
        }
    }
}

StreamFrame frameRtsp(const char *data, size_t length) {
    if (length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    return frameTextMessage(data, length, validRtspStart); // RTSP uses exact same HTTP-like Content-Length framing
}

void dissectRtsp(Context &ctx, const char *data, size_t length) {
    if (!data || length < 10) return;

    std::string_view s(data, length);
    const std::string_view firstLine = firstLineOf(s);
    if (firstLine.empty() || !validRtspStart(firstLine)) return;

    ctx.pack.protocol = "RTSP";
    ctx.pack.info = shown(firstLine);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Real Time Streaming Protocol", o, length);
        root.add(shown(firstLine), o, firstLine.size());
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
                          ", TS=" + std::to_string(timestamp) + ", SSRC=" + hexString(ssrc, 8);
    if (marker) summary += " [Marker]";

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Real-time Transport Protocol", o, std::min<size_t>(length, 12 + csrcCount * 4));
        root.add("Version: 2");
        root.add("Padding: " + std::string(padding ? "Yes" : "No"));
        root.add("Extension: " + std::string(extension ? "Yes" : "No"));
        root.add("Marker: " + std::string(marker ? "Yes" : "No"));
        root.add("Payload Type: " + std::to_string(payloadType));
        root.add("Sequence Number: " + std::to_string(seq));
        root.add("Timestamp: " + std::to_string(timestamp));
        root.add("SSRC: " + hexString(ssrc, 8));
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

    ctx.pack.info = std::string(ptName) + " (SSRC " + hexString(ssrc, 8) + ")";

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("RTP Control Protocol (" + std::string(ptName) + ")", o, pktLen <= length ? pktLen : length);
        root.add("Version: 2");
        root.add("Payload Type: " + std::string(ptName) + " (" + std::to_string(pt) + ")");
        root.add("Report Count: " + std::to_string(count));
        root.add("SSRC: " + hexString(ssrc, 8));
    }
}

} // namespace dissect

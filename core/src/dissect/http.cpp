// HTTP/1.x requests and responses, recognised by their first line (any port).
#include "protocols.h"

#include "util.h"

#include <gzip.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using packet::Field;

namespace {
    using namespace dissect;

    struct Method { const char *name; uint16_t code; };
    constexpr Method kMethods[] = {{"GET", 1}, {"POST", 2}, {"PUT", 3}, {"DELETE", 4}, {"HEAD", 5},
                                   {"OPTIONS", 6}, {"PATCH", 7}, {"CONNECT", 8}, {"TRACE", 9}};

    const char *reasonPhrase(unsigned code) {
        switch (code) {
            case 100: return "Continue";
            case 101: return "Switching Protocols";
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 206: return "Partial Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return nullptr;
        }
    }

    bool startsWith(const char *data, size_t length, const char *prefix) {
        const size_t n = std::strlen(prefix);
        return length >= n && std::memcmp(data, prefix, n) == 0;
    }

    std::string lower(std::string s) {
        for (auto &c: s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::string trim(const std::string &s) {
        size_t a = 0, b = s.size();
        while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
        while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
        return s.substr(a, b - a);
    }

    // ---- message boundaries ---------------------------------------------------------------------------------------
    constexpr size_t kMaxHeaders = 64 * 1024;           // a message whose headers are longer is not treated as HTTP
    constexpr size_t kStreamedBody = 4u << 20;          // bodies longer than this are not buffered: only the headers form the message
    constexpr uint64_t kMaxDecoded = 16u << 20;         // largest decompressed body shown

    enum class Scan { Reject, NeedMore, Done };

    // 2: `data` starts like an HTTP/1.x message, 1: could still (too few bytes), 0: it does not
    int startsLikeHttp(const char *data, size_t n) {
        int result = 0;
        auto test = [&](const char *prefix) {
            const size_t len = std::strlen(prefix), m = std::min(n, len);
            if (std::memcmp(data, prefix, m) == 0) result = std::max(result, n >= len ? 2 : 1);
        };
        for (const auto &m: kMethods) test((std::string(m.name) + " ").c_str());
        test("HTTP/1.");
        return result;
    }

    // Walks the chunks of a chunked body starting at `start`. Done: `end` is just after the last chunk and its trailers.
    Scan scanChunks(const char *d, size_t n, size_t start, size_t &end, std::string *decoded) {
        size_t pos = start;
        while (true) {
            size_t e = pos;
            while (e < n && d[e] != '\n') ++e;
            if (e >= n) return (n - pos <= 1024) ? Scan::NeedMore : Scan::Reject;
            size_t lineEnd = (e > pos && d[e - 1] == '\r') ? e - 1 : e;
            uint64_t size = 0;
            size_t digits = 0, i = pos;
            for (; i < lineEnd; ++i, ++digits) {
                const char c = d[i];
                const int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (v < 0) break;
                if (digits >= 8) return Scan::Reject;
                size = size * 16 + static_cast<uint64_t>(v);
            }
            if (digits == 0 || (i < lineEnd && d[i] != ';' && d[i] != ' ')) return Scan::Reject;
            pos = e + 1;
            if (size == 0) {   // trailers up to the empty line
                while (true) {
                    size_t t = pos;
                    while (t < n && d[t] != '\n') ++t;
                    if (t >= n) return (n - pos <= kMaxHeaders) ? Scan::NeedMore : Scan::Reject;
                    const bool empty = t == pos || (t == pos + 1 && d[pos] == '\r');
                    pos = t + 1;
                    if (empty) { end = pos; return Scan::Done; }
                }
            }
            if (n - pos < size + 1) return Scan::NeedMore;
            if (decoded) decoded->append(d + pos, size);
            pos += size;
            if (d[pos] == '\r') {
                if (n - pos < 2) return Scan::NeedMore;
                if (d[pos + 1] != '\n') return Scan::Reject;
                pos += 2;
            } else if (d[pos] == '\n') {
                ++pos;
            } else {
                return Scan::Reject;
            }
        }
    }

    struct Head {
        size_t headerEnd = 0;            // bytes of the start line and headers, including the empty line
        bool response = false;
        unsigned status = 0;
        bool chunked = false;
        bool hasLength = false;
        uint64_t length = 0;
        bool gzip = false;
        bool head = false;               // a HEAD request: its response has no body
    };

    // Reads the start line and headers; Done fills `h`.
    Scan scanHead(const char *d, size_t n, Head &h) {
        const int start = startsLikeHttp(d, n);
        if (start == 0) return Scan::Reject;
        size_t pos = 0;
        bool first = true;
        h = Head{};
        h.response = n >= 7 && std::memcmp(d, "HTTP/1.", 7) == 0;
        bool lengthSeen = false;
        while (true) {
            size_t e = pos;
            while (e < n && d[e] != '\n') {
                const unsigned char c = static_cast<unsigned char>(d[e]);
                if (first && ((c < 32 && c != '\r' && c != '\t') || c >= 127)) return Scan::Reject;
                ++e;
            }
            if (e >= n) return (n <= kMaxHeaders && start >= 1) ? Scan::NeedMore : Scan::Reject;
            if (start == 1) return Scan::NeedMore;
            const size_t textEnd = (e > pos && d[e - 1] == '\r') ? e - 1 : e;
            if (first) {
                if (textEnd == pos) return Scan::Reject;
                if (h.response) {
                    const char *sp = static_cast<const char *>(std::memchr(d, ' ', textEnd));
                    h.status = sp ? static_cast<unsigned>(std::strtol(std::string(sp + 1, d + textEnd - sp - 1).c_str(), nullptr, 10)) : 0;
                } else {
                    h.head = std::memcmp(d, "HEAD ", 5) == 0;
                }
                first = false;
            } else if (textEnd == pos) {
                h.headerEnd = e + 1;
                return Scan::Done;
            } else {
                const std::string line(d + pos, textEnd - pos);
                const size_t colon = line.find(':');
                if (colon != std::string::npos && colon > 0) {
                    const std::string name = lower(line.substr(0, colon)), value = trim(line.substr(colon + 1));
                    if (name == "content-length") {
                        uint64_t v = 0;
                        if (value.empty() || value.size() > 15) return Scan::Reject;
                        for (char c: value) {
                            if (c < '0' || c > '9') return Scan::Reject;
                            v = v * 10 + static_cast<uint64_t>(c - '0');
                        }
                        if (lengthSeen && v != h.length) return Scan::Reject;   // conflicting lengths: not a message we can trust
                        lengthSeen = h.hasLength = true;
                        h.length = v;
                    } else if (name == "transfer-encoding") {
                        h.chunked = lower(value).find("chunked") != std::string::npos;
                    } else if (name == "content-encoding") {
                        const std::string v = lower(value);
                        h.gzip = v.find("gzip") != std::string::npos;
                    }
                }
            }
            if (e - 0 > kMaxHeaders) return Scan::Reject;
            pos = e + 1;
        }
    }
} // namespace

dissect::StreamFrame dissect::frameHttp(const char *data, size_t n) {
    Head h;
    switch (scanHead(data, n, h)) {
        case Scan::Reject: return {StreamFrame::Kind::Reject, 0};
        case Scan::NeedMore: return {StreamFrame::Kind::NeedMore, 0};
        case Scan::Done: break;
    }
    const bool noBody = h.response && ((h.status >= 100 && h.status < 200) || h.status == 204 || h.status == 304);
    if (noBody) return {StreamFrame::Kind::Complete, h.headerEnd};
    if (h.chunked) {
        size_t end = 0;
        switch (scanChunks(data, n, h.headerEnd, end, nullptr)) {
            case Scan::Reject: return {StreamFrame::Kind::Reject, 0};
            case Scan::NeedMore: return {StreamFrame::Kind::NeedMore, 0};
            case Scan::Done: return {StreamFrame::Kind::Complete, end};
        }
    }
    if (h.hasLength) {
        if (h.length == 0) return {StreamFrame::Kind::Complete, h.headerEnd};
        if (h.length > kStreamedBody) return {StreamFrame::Kind::Complete, h.headerEnd};   // too large to buffer
        // the response to a HEAD request announces a length but sends no body: the next message follows right away
        if (h.response && n - h.headerEnd >= 7 && std::memcmp(data + h.headerEnd, "HTTP/1.", 7) == 0) return {StreamFrame::Kind::Complete, h.headerEnd};
        if (n - h.headerEnd < h.length) return {StreamFrame::Kind::NeedMore, 0};
        return {StreamFrame::Kind::Complete, h.headerEnd + static_cast<size_t>(h.length)};
    }
    // a request without a length has no body; a response without one runs until the server closes, which is not buffered:
    // the headers are the message and the body follows as ordinary segments
    return {StreamFrame::Kind::Complete, h.headerEnd};
}

bool dissect::dissectHttp(Context &ctx, const char *data, size_t length) {
    // 1. does the payload start like an HTTP message?
    const Method *method = nullptr;
    for (const auto &m: kMethods) {
        const size_t n = std::strlen(m.name);
        if (length > n && std::memcmp(data, m.name, n) == 0 && data[n] == ' ') { method = &m; break; }
    }
    const bool response = startsWith(data, length, "HTTP/1.");
    if (!method && !response) return false;

    // the first line must be plain printable text ending in a line break, otherwise this is not HTTP
    size_t firstEnd = 0;
    while (firstEnd < length && data[firstEnd] != '\n' && firstEnd < 8192) {
        const unsigned char c = static_cast<unsigned char>(data[firstEnd]);
        if ((c < 32 && c != '\r' && c != '\t') || c >= 127) return false;
        ++firstEnd;
    }
    if (firstEnd >= length || data[firstEnd] != '\n') return false;

    auto &pack = ctx.pack;
    const size_t o = ctx.offsetOf(data);

    // 2. split into lines (CRLF or LF) until the empty line that ends the headers
    struct Line { size_t start, end, next; };  // text is [start, end); `next` is after the line break
    std::vector<Line> lines;
    size_t pos = 0;
    bool headersComplete = false;
    while (pos < length && lines.size() < 256) {
        size_t e = pos;
        while (e < length && data[e] != '\n') ++e;
        if (e >= length) { lines.push_back({pos, length, length}); pos = length; break; } // unterminated last line
        const size_t textEnd = (e > pos && data[e - 1] == '\r') ? e - 1 : e;
        lines.push_back({pos, textEnd, e + 1});
        pos = e + 1;
        if (textEnd == lines.back().start) { headersComplete = true; break; } // the empty line
    }
    const size_t bodyStart = headersComplete ? pos : length;

    auto text = [&](const Line &l) { return std::string(data + l.start, l.end - l.start); };

    // 3. the first line
    const std::string first = text(lines[0]);
    std::string host, contentType;
    uint16_t status = 0;
    std::string uri;
    if (method) {
        const size_t sp1 = first.find(' ');
        const size_t sp2 = first.rfind(' ');
        uri = (sp2 != std::string::npos && sp2 > sp1) ? first.substr(sp1 + 1, sp2 - sp1 - 1) : first.substr(sp1 + 1);
        pack.app_type = method->code;
    } else {
        const size_t sp = first.find(' ');
        if (sp != std::string::npos) status = static_cast<uint16_t>(std::strtol(first.c_str() + sp + 1, nullptr, 10));
        pack.app_code = status;
    }

    // 4. headers
    struct Header { std::string name, value; const Line *line; };
    std::vector<Header> headers;
    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string t = text(lines[i]);
        if (t.empty()) continue;
        const size_t colon = t.find(':');
        if (colon == std::string::npos || colon == 0) continue;
        Header h{lower(t.substr(0, colon)), trim(t.substr(colon + 1)), &lines[i]};
        if (h.name == "host") host = h.value;
        if (h.name == "content-type") contentType = h.value;
        headers.push_back(std::move(h));
    }

    pack.protocol = "HTTP";
    pack.app_flags = response ? 1 : 0;
    pack.app_text = host;
    pack.app_text2 = method ? uri : contentType;
    pack.info = first;
    if (response && !contentType.empty()) {
        const size_t semi = contentType.find(';');
        pack.info += " (" + contentType.substr(0, semi) + ")";
    }

    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("Hypertext Transfer Protocol", o, length);
        Field &req = l.add(first, o + lines[0].start, lines[0].next - lines[0].start);
        if (method) {
            req.add(std::string("Request Method: ") + method->name, o, std::strlen(method->name));
            req.add("Request URI: " + uri, o + std::strlen(method->name) + 1, uri.size());
            const size_t sp2 = first.rfind(' ');
            if (sp2 != std::string::npos) req.add("Request Version: " + first.substr(sp2 + 1), o + sp2 + 1, first.size() - sp2 - 1);
        } else {
            const size_t sp = first.find(' ');
            req.add("Response Version: " + first.substr(0, sp), o, sp == std::string::npos ? first.size() : sp);
            if (sp != std::string::npos) {
                req.add("Status Code: " + std::to_string(status), o + sp + 1, 3);
                const char *reason = reasonPhrase(status);
                if (first.size() > sp + 5) req.add("Response Phrase: " + first.substr(sp + 5), o + sp + 5, first.size() - sp - 5);
                else if (reason) req.add(std::string("Response Phrase (standard): ") + reason);
            }
        }
        for (const auto &h: headers) l.add(text(*h.line), o + h.line->start, h.line->next - h.line->start);
        if (headersComplete) l.add("\\r\\n (end of headers)", o + lines.back().start, lines.back().next - lines.back().start);
        if (bodyStart < length) {
            Field &body = l.add("File Data: " + std::to_string(length - bodyStart) + " bytes", o + bodyStart, length - bodyStart);
            Head head;
            std::string payload(data + bodyStart, length - bodyStart);
            if (scanHead(data, bodyStart, head) == Scan::Done) {
                if (head.chunked) {
                    std::string plain;
                    size_t end = 0;
                    if (scanChunks(data, length, bodyStart, end, &plain) == Scan::Done) {
                        body.add("De-chunked entity body (" + std::to_string(plain.size()) + " bytes)", o + bodyStart, length - bodyStart);
                        payload = std::move(plain);
                    }
                }
                if (head.gzip && !payload.empty()) {
                    std::string inflated, error;
                    if (core::gunzipMemory(payload, inflated, kMaxDecoded, error)) {
                        body.add("Content-encoded entity body (gzip): " + std::to_string(payload.size()) + " bytes -> " + std::to_string(inflated.size()) + " bytes",
                                 o + bodyStart, length - bodyStart);
                    } else {
                        body.add("[Could not decompress the gzip body: " + error + "]");
                    }
                }
            }
        }
        if (!headersComplete) l.add("[Headers continue in later segments]");
    }
    return true;
}

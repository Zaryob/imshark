// HTTP/1.x requests and responses, recognised by their first line (any port).
#include "protocols.h"

#include "util.h"

#include <cctype>
#include <cstdlib>
#include <cstring>

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
} // namespace

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
        if (sp != std::string::npos) status = static_cast<uint16_t>(std::atoi(first.c_str() + sp + 1));
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
        if (bodyStart < length) l.add("File Data: " + std::to_string(length - bodyStart) + " bytes", o + bodyStart, length - bodyStart);
        if (!headersComplete) l.add("[Headers continue in later segments]");
    }
    return true;
}

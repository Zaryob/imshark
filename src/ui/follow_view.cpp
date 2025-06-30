#include "follow_view.h"

#include <cstdio>

namespace {
    bool wanted(ui::FollowDirection d, stream::Direction chunk) {
        return d == ui::FollowDirection::Both || (d == ui::FollowDirection::AtoB) == (chunk == stream::Direction::AtoB);
    }

    char printable(unsigned char c) { return (c >= 32 && c < 127) ? static_cast<char>(c) : '.'; }
} // namespace

std::vector<ui::FollowLine> ui::buildFollowLines(const stream::Stream &s, FollowDirection direction, FollowView view,
                                                 size_t maxLineLength) {
    std::vector<FollowLine> lines;
    if (maxLineLength == 0) maxLineLength = 160;

    for (const auto &chunk: s.chunks) {
        if (!wanted(direction, chunk.direction)) continue;

        if (chunk.missingBefore > 0) {
            lines.push_back({FollowLine::Kind::Gap, chunk.direction, "[... " + std::to_string(chunk.missingBefore) + " bytes not captured ...]"});
        }

        if (view == FollowView::HexDump) {
            for (size_t pos = 0; pos < chunk.data.size(); pos += 16) {
                char head[16];
                std::snprintf(head, sizeof(head), "%08zx  ", pos);
                std::string hex, ascii;
                for (size_t i = pos; i < pos + 16; ++i) {
                    if (i < chunk.data.size()) {
                        char b[4];
                        std::snprintf(b, sizeof(b), "%02x ", static_cast<unsigned char>(chunk.data[i]));
                        hex += b;
                        ascii += printable(static_cast<unsigned char>(chunk.data[i]));
                    } else {
                        hex += "   ";
                    }
                    if (i == pos + 7) hex += ' ';
                }
                lines.push_back({FollowLine::Kind::Data, chunk.direction, head + hex + " " + ascii});
            }
            continue;
        }

        // ASCII: split at line ends, wrap long lines
        std::string current;
        auto flush = [&] {
            lines.push_back({FollowLine::Kind::Data, chunk.direction, current});
            current.clear();
        };
        bool pendingCr = false;
        for (unsigned char c: chunk.data) {
            if (c == '\n') { flush(); pendingCr = false; continue; }
            if (pendingCr) { current += '.'; pendingCr = false; } // a lone CR is shown, not swallowed
            if (c == '\r') { pendingCr = true; continue; }
            current += printable(c);
            if (current.size() >= maxLineLength) flush();
        }
        if (pendingCr) current += '.';
        if (!current.empty()) flush();
    }
    return lines;
}

std::string ui::followText(const std::vector<FollowLine> &lines) {
    std::string out;
    for (const auto &l: lines) out += l.text + "\n";
    return out;
}

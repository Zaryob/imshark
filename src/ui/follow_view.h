#pragma once

#include <string>
#include <vector>

#include <stream/follow.h>

namespace ui {
    enum class FollowView : int { Ascii = 0, HexDump = 1 };
    enum class FollowDirection : int { Both = 0, AtoB = 1, BtoA = 2 };
    /// What a TCP stream shows: the bytes as captured, or the application data of its TLS records decrypted with the key log.
    enum class FollowStreamMode : int { Tcp = 0, TlsDecrypted = 1 };

    /// One display line of the stream window.
    struct FollowLine {
        enum class Kind { Data, Gap } kind = Kind::Data;
        stream::Direction direction = stream::Direction::AtoB;
        std::string text;
    };

    /// Turns the reassembled stream into display lines for the chosen direction filter and view.
    ///  - Ascii:   text split at line ends (CR/LF), unprintable bytes shown as '.', very long lines wrapped
    ///  - HexDump: 16 bytes per line: offset, hex bytes, ASCII
    /// TCP gaps appear as "[... N bytes not captured ...]" lines.
    std::vector<FollowLine> buildFollowLines(const stream::Stream &stream, FollowDirection direction, FollowView view,
                                             size_t maxLineLength = 160);

    /// The raw payload bytes of the chosen direction (or both, in arrival order) - what "Save As" writes.
    std::string followRawBytes(const stream::Stream &stream, FollowDirection direction);

    /// The plain text of the lines (what "Copy" puts on the clipboard).
    std::string followText(const std::vector<FollowLine> &lines);
} // namespace ui

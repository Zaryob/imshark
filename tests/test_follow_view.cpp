#include <gtest/gtest.h>

#include <ui/follow_view.h>

namespace {
    stream::Stream make() {
        stream::Stream s;
        s.chunks = {
            {stream::Direction::AtoB, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 0, 4},
            {stream::Direction::BtoA, "HTTP/1.1 200 OK\nline2", 0, 5},
            {stream::Direction::AtoB, "tail", 7, 9},
        };
        return s;
    }
} // namespace

TEST(FollowView, AsciiSplitsLinesAndKeepsDirections) {
    const auto lines = ui::buildFollowLines(make(), ui::FollowDirection::Both, ui::FollowView::Ascii);
    std::vector<std::string> texts;
    for (const auto &l: lines) texts.push_back(l.text);
    EXPECT_EQ(texts, (std::vector<std::string>{"GET / HTTP/1.1", "Host: x", "", "HTTP/1.1 200 OK", "line2",
                                               "[... 7 bytes not captured ...]", "tail"}));
    EXPECT_EQ(lines[0].direction, stream::Direction::AtoB);
    EXPECT_EQ(lines[3].direction, stream::Direction::BtoA);
    EXPECT_EQ(lines[5].kind, ui::FollowLine::Kind::Gap);
    EXPECT_EQ(lines[6].kind, ui::FollowLine::Kind::Data);
}

TEST(FollowView, DirectionFilter) {
    const auto a = ui::buildFollowLines(make(), ui::FollowDirection::AtoB, ui::FollowView::Ascii);
    for (const auto &l: a) EXPECT_EQ(l.direction, stream::Direction::AtoB);
    EXPECT_EQ(a.size(), 5u);   // 3 lines, the gap note and "tail"
    const auto b = ui::buildFollowLines(make(), ui::FollowDirection::BtoA, ui::FollowView::Ascii);
    ASSERT_EQ(b.size(), 2u);
    EXPECT_EQ(b[1].text, "line2");
}

TEST(FollowView, UnprintableBytesAndLoneCarriageReturns) {
    stream::Stream s;
    s.chunks = {{stream::Direction::AtoB, std::string("a\0b\x01\xff\rc\r\nd", 10), 0, 1}};
    const auto lines = ui::buildFollowLines(s, ui::FollowDirection::Both, ui::FollowView::Ascii);
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_EQ(lines[0].text, "a.b.." ".c") << "a lone CR is shown as '.', CR+LF ends the line";
    EXPECT_EQ(lines[1].text, "d");
}

TEST(FollowView, LongLinesAreWrapped) {
    stream::Stream s;
    s.chunks = {{stream::Direction::AtoB, std::string(250, 'x'), 0, 1}};
    const auto lines = ui::buildFollowLines(s, ui::FollowDirection::Both, ui::FollowView::Ascii, 100);
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_EQ(lines[0].text.size(), 100u);
    EXPECT_EQ(lines[2].text.size(), 50u);
    EXPECT_EQ(ui::buildFollowLines(s, ui::FollowDirection::Both, ui::FollowView::Ascii, 0).size(), 2u) << "0 falls back to the default width";
}

TEST(FollowView, HexDump) {
    stream::Stream s;
    s.chunks = {{stream::Direction::BtoA, "ABCDEFGHIJKLMNOPQRS", 0, 1}};
    const auto lines = ui::buildFollowLines(s, ui::FollowDirection::Both, ui::FollowView::HexDump);
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_EQ(lines[0].text, "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP");
    EXPECT_EQ(lines[1].text, "00000010  51 52 53                                          QRS");
    EXPECT_EQ(lines[0].direction, stream::Direction::BtoA);
}

TEST(FollowView, TextForTheClipboardAndEmptyStreams) {
    EXPECT_EQ(ui::followText(ui::buildFollowLines(make(), ui::FollowDirection::BtoA, ui::FollowView::Ascii)), "HTTP/1.1 200 OK\nline2\n");
    EXPECT_TRUE(ui::buildFollowLines(stream::Stream(), ui::FollowDirection::Both, ui::FollowView::Ascii).empty());
    EXPECT_EQ(ui::followText({}), "");
}

TEST(FollowView, RawBytesOfTheChosenDirection) {
    const auto s = make();
    EXPECT_EQ(ui::followRawBytes(s, ui::FollowDirection::AtoB), std::string("GET / HTTP/1.1\r\nHost: x\r\n\r\ntail"));
    EXPECT_EQ(ui::followRawBytes(s, ui::FollowDirection::BtoA), "HTTP/1.1 200 OK\nline2");
    EXPECT_EQ(ui::followRawBytes(s, ui::FollowDirection::Both), "GET / HTTP/1.1\r\nHost: x\r\n\r\nHTTP/1.1 200 OK\nline2tail");
    stream::Stream binary;
    binary.chunks = {{stream::Direction::AtoB, std::string("\0\xff\x01", 3), 0, 1}};
    EXPECT_EQ(ui::followRawBytes(binary, ui::FollowDirection::Both).size(), 3u) << "binary data is kept exactly";
    EXPECT_EQ(ui::followRawBytes(stream::Stream(), ui::FollowDirection::Both), "");
}

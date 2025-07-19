#include <gtest/gtest.h>

#include <ui/clipboard.h>

#include "support.h"

TEST(Clipboard, FieldValueIsTheTextAfterTheFirstColon) {
    packet::Field f{"Source Port: 443", 0, 2, {}};
    EXPECT_EQ(ui::fieldValue(f), "443");
    packet::Field g{"Sequence Number: 1 (relative), 100: raw", 0, 4, {}};
    EXPECT_EQ(ui::fieldValue(g), "1 (relative), 100: raw") << "only the first separator counts";
    packet::Field h{"Frame 1: 42 bytes on wire", 0, 42, {}};
    EXPECT_EQ(ui::fieldValue(h), "42 bytes on wire");
    packet::Field plain{"Options", 0, 4, {}};
    EXPECT_EQ(ui::fieldValue(plain), "Options");
}

TEST(Clipboard, HexAndAscii) {
    const auto data = support::hex("48 65 6c 6c 6f 00 ff 20");
    EXPECT_EQ(ui::bytesToHex(data, 0, 5), "48 65 6c 6c 6f");
    EXPECT_EQ(ui::bytesToHex(data, 5, 3), "00 ff 20");
    EXPECT_EQ(ui::bytesToAscii(data, 0, 8), "Hello.. ");
    EXPECT_EQ(ui::bytesToHex(data, 6, 100), "ff 20") << "ranges are clamped to the data";
    EXPECT_EQ(ui::bytesToHex(data, 50, 4), "") << "a range past the end is empty, not a crash";
    EXPECT_EQ(ui::bytesToAscii(data, 50, 4), "");
}

TEST(Clipboard, HexDumpHasAlignedColumns) {
    std::vector<char> data;
    for (int i = 0; i < 20; ++i) data.push_back(static_cast<char>('A' + i));
    const auto dump = ui::hexDump(data);
    const std::string expected =
        "000000  41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP\n"
        "000010  51 52 53 54                                      QRST\n";
    EXPECT_EQ(dump, expected);
    EXPECT_EQ(ui::hexDump({}), "");
}

TEST(Clipboard, SummaryRowIsTabSeparated) {
    packet::PacketInfo p(3);
    p.time = 1.5;
    p.source = "10.0.0.1";
    p.destination = "10.0.0.2";
    p.protocol = "TCP";
    p.frame_length = 60;
    p.info = "1 -> 2 [SYN]";
    EXPECT_EQ(ui::summaryRow(p), "3\t1.500000\t10.0.0.1\t10.0.0.2\tTCP\t60\t1 -> 2 [SYN]");
}

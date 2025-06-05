#include <gtest/gtest.h>

#include <ui/time_format.h>

TEST(TimeFormat, UtcKnownInstants) {
    EXPECT_EQ(ui::formatUtc(0), "1970-01-01 00:00:00.000000");
    EXPECT_EQ(ui::formatUtc(1700000000.0), "2023-11-14 22:13:20.000000");
    EXPECT_EQ(ui::formatUtc(1700000000.123456), "2023-11-14 22:13:20.123456");
    EXPECT_EQ(ui::formatUtc(951782400.0), "2000-02-29 00:00:00.000000") << "leap day";
    EXPECT_EQ(ui::formatUtc(1709164799.999999), "2024-02-28 23:59:59.999999");
    EXPECT_EQ(ui::formatUtc(1709164800.0), "2024-02-29 00:00:00.000000");
    EXPECT_EQ(ui::formatUtc(4102444800.0), "2100-01-01 00:00:00.000000") << "2100 is not a leap year";
    EXPECT_EQ(ui::formatUtc(-1.0), "1969-12-31 23:59:59.000000");
    EXPECT_EQ(ui::formatUtc(-0.5), "1969-12-31 23:59:59.500000");
    EXPECT_EQ(ui::formatUtc(86399.0), "1970-01-01 23:59:59.000000");
}

TEST(TimeFormat, PacketTimeInAllFormats) {
    packet::PacketInfo a(1), b(2);
    a.time = 0;
    b.time = 2.5;
    const double start = 1700000000.0;
    EXPECT_EQ(ui::formatPacketTime(b, &a, start, ui::TimeFormat::SinceCaptureStart), "2.500000");
    EXPECT_EQ(ui::formatPacketTime(b, &a, start, ui::TimeFormat::SincePrevious), "2.500000");
    EXPECT_EQ(ui::formatPacketTime(a, nullptr, start, ui::TimeFormat::SincePrevious), "0.000000") << "the first packet has no previous one";
    EXPECT_EQ(ui::formatPacketTime(b, &a, start, ui::TimeFormat::UtcDateTime), "2023-11-14 22:13:22.500000");
    EXPECT_EQ(ui::formatPacketTime(b, &a, start, ui::TimeFormat::EpochSeconds), "1700000002.500000");
}

TEST(TimeFormat, KeysRoundTripAndUnknownKeysFallBack) {
    for (auto f: {ui::TimeFormat::SinceCaptureStart, ui::TimeFormat::SincePrevious, ui::TimeFormat::UtcDateTime, ui::TimeFormat::EpochSeconds}) {
        EXPECT_EQ(ui::timeFormatFromKey(ui::timeFormatKey(f)), f);
        EXPECT_NE(std::string(ui::timeFormatName(f)), "");
    }
    EXPECT_EQ(ui::timeFormatFromKey("garbage"), ui::TimeFormat::SinceCaptureStart);
}

#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

using support::put;

namespace {
    const std::vector<char> kFrame = support::hex(support::kArpRequest);

    // pcapng option: code, length, value padded to 4 bytes
    void option(std::vector<char> &out, bool be, uint16_t code, const std::string &value) {
        put<uint16_t>(out, code, be);
        put<uint16_t>(out, static_cast<uint16_t>(value.size()), be);
        out.insert(out.end(), value.begin(), value.end());
        out.insert(out.end(), (4 - value.size() % 4) % 4, 0);
    }
    void endOptions(std::vector<char> &out, bool be) { put<uint32_t>(out, 0, be); }

    std::vector<char> block(bool be, uint32_t type, const std::vector<char> &body) {
        std::vector<char> b;
        const uint32_t total = 12 + static_cast<uint32_t>(body.size());
        put(b, type, be);
        put(b, total, be);
        b.insert(b.end(), body.begin(), body.end());
        put(b, total, be);
        return b;
    }

    std::string u64(bool be, uint64_t v) {
        std::vector<char> tmp;
        put<uint64_t>(tmp, v, be);
        return std::string(tmp.begin(), tmp.end());
    }

    void append(std::vector<char> &to, const std::vector<char> &b) { to.insert(to.end(), b.begin(), b.end()); }

    std::vector<char> shb(bool be, bool withOptions = true) {
        std::vector<char> body;
        put<uint32_t>(body, 0x1A2B3C4D, be);
        put<uint16_t>(body, 1, be);
        put<uint16_t>(body, 0, be);
        put<int64_t>(body, -1, be);
        if (withOptions) {
            option(body, be, 1, "captured during the outage");
            option(body, be, 2, "Intel(R) NIC");
            option(body, be, 3, "Linux 6.1");
            option(body, be, 4, "dumpcap 4.2");
            endOptions(body, be);
        }
        return block(be, 0x0A0D0D0A, body);
    }

    std::vector<char> idb(bool be, uint16_t linkType, const std::string &name, const std::string &description, int tsresol) {
        std::vector<char> body;
        put<uint16_t>(body, linkType, be);
        put<uint16_t>(body, 0, be);
        put<uint32_t>(body, 65535, be);
        if (!name.empty()) option(body, be, 2, name);
        if (!description.empty()) option(body, be, 3, description);
        if (tsresol >= 0) option(body, be, 9, std::string(1, static_cast<char>(tsresol)));
        endOptions(body, be);
        return block(be, 1, body);
    }

    std::vector<char> epb(bool be, uint32_t iface, uint64_t ticks, const std::string &comment = "") {
        std::vector<char> body;
        put<uint32_t>(body, iface, be);
        put<uint32_t>(body, static_cast<uint32_t>(ticks >> 32), be);
        put<uint32_t>(body, static_cast<uint32_t>(ticks & 0xffffffff), be);
        put<uint32_t>(body, static_cast<uint32_t>(kFrame.size()), be);
        put<uint32_t>(body, static_cast<uint32_t>(kFrame.size()), be);
        body.insert(body.end(), kFrame.begin(), kFrame.end());
        body.insert(body.end(), (4 - kFrame.size() % 4) % 4, 0);
        if (!comment.empty()) { option(body, be, 1, comment); endOptions(body, be); }
        return block(be, 6, body);
    }

    std::vector<char> isb(bool be, uint32_t iface, uint64_t received, uint64_t dropped) {
        std::vector<char> body;
        put<uint32_t>(body, iface, be);
        put<uint32_t>(body, 0, be);
        put<uint32_t>(body, 0, be);
        option(body, be, 4, u64(be, received));
        option(body, be, 5, u64(be, dropped));
        endOptions(body, be);
        return block(be, 5, body);
    }

    std::vector<char> nrb(bool be) {
        std::vector<char> body;
        // ipv4 record: 10.0.0.1 -> "gateway.local", "gw"
        std::string v4 = std::string("\x0a\x00\x00\x01", 4) + "gateway.local" + '\0' + "gw" + '\0';
        put<uint16_t>(body, 1, be);
        put<uint16_t>(body, static_cast<uint16_t>(v4.size()), be);
        body.insert(body.end(), v4.begin(), v4.end());
        body.insert(body.end(), (4 - v4.size() % 4) % 4, 0);
        // ipv6 record: 2001:db8::1 -> "v6host"
        std::string v6 = std::string("\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) + "v6host" + '\0';
        put<uint16_t>(body, 2, be);
        put<uint16_t>(body, static_cast<uint16_t>(v6.size()), be);
        body.insert(body.end(), v6.begin(), v6.end());
        body.insert(body.end(), (4 - v6.size() % 4) % 4, 0);
        endOptions(body, be);
        return block(be, 4, body);
    }

    std::vector<char> richCapture(bool be) {
        std::vector<char> f;
        append(f, shb(be));
        append(f, idb(be, 1, "eth0", "uplink", 9));
        append(f, epb(be, 0, 1000000000ull * 5));
        append(f, epb(be, 0, 1000000000ull * 6, "suspicious"));
        append(f, nrb(be));
        append(f, epb(be, 0, 1000000000ull * 7));
        append(f, isb(be, 0, 100, 7));
        return f;
    }

    struct Loaded {
        std::vector<packet::PacketInfo> packets;
        core::CaptureInfo info;
        std::string path, message;
        bool ok = false;
        Loaded(const std::vector<char> &bytes, bool pcapng = true) {
            path = support::writeTemp("info.bin", bytes);
            core::FileProcessor fp;
            ok = pcapng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message);
            info = fp.captureInfo();
        }
        ~Loaded() { std::remove(path.c_str()); }
    };
} // namespace

TEST(CaptureInfo, PcapngMetadataInBothByteOrders) {
    for (bool be: {false, true}) {
        SCOPED_TRACE(be ? "big endian" : "little endian");
        Loaded cap(richCapture(be));
        ASSERT_TRUE(cap.ok) << cap.message;
        const auto &info = cap.info;
        EXPECT_EQ(info.format, std::string("pcapng (") + (be ? "big" : "little") + " endian), version 1.0");
        EXPECT_EQ(info.sections, 1u);
        EXPECT_EQ(info.comment, "captured during the outage");
        EXPECT_EQ(info.hardware, "Intel(R) NIC");
        EXPECT_EQ(info.os, "Linux 6.1");
        EXPECT_EQ(info.application, "dumpcap 4.2");
        EXPECT_EQ(info.fileSize, richCapture(be).size());

        ASSERT_EQ(info.interfaces.size(), 1u);
        const auto &itf = info.interfaces[0];
        EXPECT_EQ(itf.name, "eth0");
        EXPECT_EQ(itf.description, "uplink");
        EXPECT_EQ(itf.linkType, 1u);
        EXPECT_EQ(itf.snapLen, 65535u);
        EXPECT_EQ(itf.ticksPerSecond, 1000000000ull);
        EXPECT_EQ(itf.packets, 3u);
        EXPECT_TRUE(itf.hasStats);
        EXPECT_EQ(itf.received, 100u);
        EXPECT_EQ(itf.dropped, 7u);

        ASSERT_EQ(info.names.size(), 3u);
        EXPECT_EQ(info.names[0].address, "10.0.0.1");
        EXPECT_EQ(info.names[0].name, "gateway.local");
        EXPECT_EQ(info.names[1].name, "gw");
        EXPECT_EQ(info.names[2].address, "2001:db8::1");
        EXPECT_EQ(info.names[2].name, "v6host");

        ASSERT_EQ(info.packetComments.size(), 1u);
        EXPECT_EQ(info.packetComments.at(2), "suspicious");
        ASSERT_EQ(cap.packets.size(), 3u);
        EXPECT_FALSE(cap.packets[0].has_comment);
        EXPECT_TRUE(cap.packets[1].has_comment);
        EXPECT_FALSE(cap.packets[2].has_comment);
        EXPECT_NEAR(cap.packets[2].time, 2.0, 1e-9) << "nanosecond resolution from the interface option";
    }
}

TEST(CaptureInfo, CommentFilterAndDetails) {
    Loaded cap(richCapture(false));
    auto f = filter::Filter::compile("frame.comment");
    ASSERT_TRUE(f.ok);
    std::vector<int> hits;
    for (const auto &p: cap.packets) if (f.filter.matches(p)) hits.push_back(p.number);
    EXPECT_EQ(hits, std::vector<int>{2});

    packet::PacketInfo with, without;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[1], with, &cap.packets, &cap.info));
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[0], without, &cap.packets, &cap.info));
    bool found = false;
    for (const auto &c: with.fields[0].children) if (c.text == "Packet comment: suspicious") found = true;
    EXPECT_TRUE(found);
    for (const auto &c: without.fields[0].children) EXPECT_NE(c.text.rfind("Packet comment", 0), 0u);

    packet::PacketInfo noInfo;   // without the capture info the comment simply is not shown
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[1], noInfo, &cap.packets));
}

TEST(CaptureInfo, SeveralSectionsKeepTheirInterfacesApart) {
    std::vector<char> f;
    append(f, shb(false));
    append(f, idb(false, 1, "first", "", -1));
    append(f, epb(false, 0, 1000000));
    append(f, isb(false, 0, 10, 1));
    append(f, shb(false, false));
    append(f, idb(false, 113, "second", "", 6));
    append(f, epb(false, 0, 2000000));
    append(f, epb(false, 0, 3000000));
    append(f, isb(false, 0, 20, 2));
    Loaded cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    EXPECT_EQ(cap.info.sections, 2u);
    ASSERT_EQ(cap.info.interfaces.size(), 2u);
    EXPECT_EQ(cap.info.interfaces[0].name, "first");
    EXPECT_EQ(cap.info.interfaces[0].packets, 1u);
    EXPECT_EQ(cap.info.interfaces[0].received, 10u);
    EXPECT_EQ(cap.info.interfaces[1].name, "second");
    EXPECT_EQ(cap.info.interfaces[1].linkType, 113u);
    EXPECT_EQ(cap.info.interfaces[1].packets, 2u);
    EXPECT_EQ(cap.info.interfaces[1].received, 20u);
    EXPECT_EQ(cap.info.comment, "captured during the outage") << "only the first section's metadata is kept";
}

TEST(CaptureInfo, ClassicPcapInfo) {
    const auto bytes = support::pcapBytes({kFrame, kFrame, kFrame});
    Loaded cap(bytes, false);
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(cap.info.format, "pcap (little endian, microsecond timestamps), version 2.4");
    EXPECT_EQ(cap.info.fileSize, bytes.size());
    ASSERT_EQ(cap.info.interfaces.size(), 1u);
    EXPECT_EQ(cap.info.interfaces[0].packets, 3u);
    EXPECT_EQ(cap.info.interfaces[0].linkType, 1u);
    EXPECT_EQ(cap.info.interfaces[0].snapLen, 65535u);
    EXPECT_EQ(cap.info.interfaces[0].ticksPerSecond, 1000000u);
    EXPECT_TRUE(cap.info.packetComments.empty());
    EXPECT_TRUE(cap.info.names.empty());
}

TEST(CaptureInfo, ProcessingAnotherFileResetsTheInfo) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const auto a = support::writeTemp("info_a.pcapng", richCapture(false));
    ASSERT_TRUE(fp.processPcapngFile(a, packets, message));
    EXPECT_EQ(fp.captureInfo().interfaces[0].name, "eth0");
    const auto b = support::writeTemp("info_b.pcap", support::pcapBytes({kFrame}));
    packets.clear();
    ASSERT_TRUE(fp.processPcapFile(b, packets, message));
    EXPECT_EQ(fp.captureInfo().interfaces.size(), 1u);
    EXPECT_EQ(fp.captureInfo().interfaces[0].name, "");
    EXPECT_TRUE(fp.captureInfo().packetComments.empty());
    std::remove(a.c_str());
    std::remove(b.c_str());
}

TEST(CaptureInfo, DamagedOptionsAndRecordsNeverCrash) {
    std::mt19937 rng(23);
    const std::vector<std::vector<char>> seeds = {richCapture(false), richCapture(true)};
    for (int i = 0; i < 3000; ++i) {
        auto data = seeds[rng() % 2];
        for (unsigned k = 1 + rng() % 8; k > 0; --k) data[rng() % data.size()] = static_cast<char>(rng());
        if (i % 4 == 0) data.resize(rng() % data.size());
        Loaded cap(data);   // must not crash; success or a message are both fine
        (void)cap.ok;
    }
}

// ---- if_tsoffset and undefined interfaces --------------------------------------------------------------------

namespace {
    std::vector<char> idbWithOffset(bool be, uint16_t linkType, int tsresol, int64_t offsetSeconds, int fcsLen = -1) {
        std::vector<char> body;
        put<uint16_t>(body, linkType, be);
        put<uint16_t>(body, 0, be);
        put<uint32_t>(body, 65535, be);
        if (tsresol >= 0) option(body, be, 9, std::string(1, static_cast<char>(tsresol)));
        if (offsetSeconds != 0) option(body, be, 14, u64(be, static_cast<uint64_t>(offsetSeconds)));
        if (fcsLen >= 0) option(body, be, 13, std::string(1, static_cast<char>(fcsLen)));
        endOptions(body, be);
        return block(be, 1, body);
    }

    std::vector<char> spb(bool be) {
        std::vector<char> body;
        put<uint32_t>(body, static_cast<uint32_t>(kFrame.size()), be);
        body.insert(body.end(), kFrame.begin(), kFrame.end());
        body.insert(body.end(), (4 - kFrame.size() % 4) % 4, 0);
        return block(be, 3, body);
    }
}

TEST(PcapngTimeOffset, IsAddedToTheTimestampsOfItsInterface) {
    for (bool be: {false, true}) {
        SCOPED_TRACE(be ? "big endian" : "little endian");
        std::vector<char> f;
        append(f, shb(be, false));
        append(f, idbWithOffset(be, 1, 6, 1000));          // microseconds, +1000 s
        append(f, idbWithOffset(be, 1, 6, 1100));          // another interface, +1100 s
        append(f, epb(be, 0, 5000000));                    // 5 s (+1000)  = 1005
        append(f, epb(be, 1, 5000000));                    // 5 s (+1100)  = 1105
        append(f, epb(be, 0, 6500000));                    // 6.5 s (+1000) = 1006.5
        Loaded cap(f);
        ASSERT_TRUE(cap.ok) << cap.message;
        ASSERT_EQ(cap.packets.size(), 3u);
        EXPECT_NEAR(cap.packets[0].time, 0.0, 1e-9);
        EXPECT_NEAR(cap.packets[1].time, 100.0, 1e-6) << "the second interface's clock is 100 s ahead";
        EXPECT_NEAR(cap.packets[2].time, 1.5, 1e-6);

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        ASSERT_TRUE(fp.processPcapngFile(cap.path, packets, message));
        EXPECT_NEAR(fp.captureStartEpoch(), 1005.0, 1e-6) << "absolute start time includes the offset";
    }
}

TEST(PcapngTimeOffset, NegativeOffsetsAndNoOffset) {
    std::vector<char> f;
    append(f, shb(false, false));
    append(f, idbWithOffset(false, 1, 6, -3600));
    append(f, epb(false, 0, 7200000000ull));               // 7200 s - 3600 s = 3600 s
    append(f, epb(false, 0, 7201000000ull));
    Loaded cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    EXPECT_NEAR(cap.packets[1].time - cap.packets[0].time, 1.0, 1e-9);
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapngFile(cap.path, packets, message));
    EXPECT_NEAR(fp.captureStartEpoch(), 3600.0, 1e-6);

    std::vector<char> plain;
    append(plain, shb(false, false));
    append(plain, idbWithOffset(false, 1, 6, 0));
    append(plain, epb(false, 0, 2000000));
    core::FileProcessor fp2;
    std::vector<packet::PacketInfo> p2;
    const auto path = support::writeTemp("tsoffset_plain.pcapng", plain);
    ASSERT_TRUE(fp2.processPcapngFile(path, p2, message));
    EXPECT_NEAR(fp2.captureStartEpoch(), 2.0, 1e-6);
    std::remove(path.c_str());
}

TEST(PcapngInterfaces, UndefinedInterfaceIsNotGuessedToBeEthernet) {
    std::vector<char> f;
    append(f, shb(false, false));
    append(f, idbWithOffset(false, 1, -1, 0));
    append(f, epb(false, 0, 1000000));                     // fine
    append(f, epb(false, 7, 2000000));                     // interface 7 does not exist
    append(f, epb(false, 0, 3000000));
    Loaded cap(f);
    ASSERT_TRUE(cap.ok);
    ASSERT_EQ(cap.packets.size(), 3u) << "the packet is kept";
    EXPECT_EQ(cap.packets[0].protocol, "ARP");
    EXPECT_EQ(cap.packets[1].link_type, packet::kUndefinedLinkType);
    EXPECT_EQ(cap.packets[1].protocol, "Unknown");
    EXPECT_EQ(cap.packets[1].info, "Packet refers to an undefined capture interface");
    EXPECT_EQ(cap.packets[2].protocol, "ARP") << "neighbouring packets are not affected";
    EXPECT_NE(cap.message.find("interface 7"), std::string::npos) << cap.message;
    EXPECT_NE(cap.message.find("1 packet(s)"), std::string::npos) << cap.message;
    EXPECT_EQ(cap.info.interfaces[0].packets, 2u) << "only packets of a defined interface are counted";
}

TEST(PcapngInterfaces, SimplePacketBlocksWithoutAnyInterface) {
    std::vector<char> f;
    append(f, shb(false, false));
    append(f, spb(false));                                 // an SPB needs interface 0, but none was defined
    Loaded cap(f);
    ASSERT_TRUE(cap.ok);
    ASSERT_EQ(cap.packets.size(), 1u);
    EXPECT_EQ(cap.packets[0].link_type, packet::kUndefinedLinkType);
    EXPECT_FALSE(cap.message.empty());
}

TEST(PcapngInterfaces, InterfacesAreScopedToTheirSection) {
    std::vector<char> f;
    append(f, shb(false, false));
    append(f, idbWithOffset(false, 1, -1, 0));
    append(f, epb(false, 0, 1000000));
    append(f, shb(false, false));                          // new section: interface 0 of the old one is gone
    append(f, epb(false, 0, 2000000));
    Loaded cap(f);
    ASSERT_TRUE(cap.ok);
    ASSERT_EQ(cap.packets.size(), 2u);
    EXPECT_EQ(cap.packets[0].protocol, "ARP");
    EXPECT_EQ(cap.packets[1].link_type, packet::kUndefinedLinkType);
}

TEST(PcapngInterfaces, FcsLengthOptionIsUsedPerInterface) {
    std::vector<char> f;
    append(f, shb(false, false));
    append(f, idbWithOffset(false, 1, -1, 0, 4));          // 4 FCS bytes per frame
    append(f, idbWithOffset(false, 1, -1, 0));             // none
    append(f, epb(false, 0, 1000000));
    append(f, epb(false, 1, 2000000));
    Loaded cap(f);
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(cap.packets[0].fcs_length, 4);
    EXPECT_EQ(cap.packets[1].fcs_length, 0);
    EXPECT_EQ(cap.info.interfaces[0].packets, 1u);
    EXPECT_EQ(cap.info.interfaces[1].packets, 1u);
}

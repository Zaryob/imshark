// The ESP-NULL heuristic (RFC 4303 + RFC 2410) and the ESP dissector built on it.
//
// Oracle: the ESP packets below were built by an independent script (Python standard library only) from the RFC 4303 section 2
// layout - SPI, sequence number, payload, padding 1..n, pad length, next header - with real ICVs (RFC 2404 HMAC-SHA1-96 and
// RFC 4868 HMAC-SHA-256-128 over everything from the SPI to the next header) and the inner IPv4 / ICMP checksums computed
// independently (RFC 1071). The generator is kept in the task report; it prints these arrays.
#include <gtest/gtest.h>

#include <filesystem>
#include <functional>
#include <random>

#include <core.h>
#include <dissect/esp_null.h>
#include <filter/filter.h>
#include <stats/statistics.h>
#include <ui/settings.h>

#include "frame_sweep.h"
#include "ipsec_support.h"
#include "support.h"

using namespace ipsectest;

namespace {
    using framesweep::Bytes;

    // transport mode, TCP (SYN, 4 data bytes), HMAC-SHA1-96
    const Bytes kEspTcp = {0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x50, 0x30, 0x39, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x69, 0x6e, 0x67, 0x01, 0x02, 0x02, 0x06, 0x2c, 0x24, 0x61, 0x92, 0x1a, 0x4a, 0xda, 0x34, 0xcc, 0x3c, 0x91, 0x84};
    // transport mode, UDP 4000 -> 5000 "hello", HMAC-SHA-256-128 (16 byte ICV)
    const Bytes kEspUdp = {0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x06, 0x0f, 0xa0, 0x13, 0x88, 0x00, 0x0d, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x01, 0x01, 0x11, 0xf9, 0x99, 0xe7, 0xb8, 0x3b, 0x11, 0x94, 0xd9, 0xdf, 0xca, 0xb2, 0xd9, 0x00, 0x29, 0xd4, 0x8a};
    // tunnel mode: an IPv4 packet (192.168.0.1 -> 192.168.0.2, ICMP echo) inside, HMAC-SHA1-96
    const Bytes kEspTunnel = {0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x07, 0x45, 0x00, 0x00, 0x20, 0x00, 0x07, 0x00, 0x00, 0x40, 0x01, 0xf9, 0x82, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x08, 0x00, 0x21, 0x04, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x01, 0x02, 0x02, 0x04, 0x12, 0x21, 0xd8, 0x2f, 0xf4, 0x2b, 0x69, 0xcd, 0x7f, 0xed, 0x36, 0x66};

    dissect::EspNullResult inspect(const Bytes &esp) { return dissect::inspectEspNull(esp.data() + 8, esp.size() - 8); }

    Bytes ipFrame(const Bytes &esp) { return framesweep::ethernet(0x0800, framesweep::ipv4Packet(50, esp)); }

} // namespace

TEST(EspNull, RecognisesTheIndependentlyBuiltPackets) {
    auto r = inspect(kEspTcp);
    EXPECT_TRUE(r.plaintext);
    EXPECT_EQ(r.nextHeader, 6);
    EXPECT_EQ(r.payloadLength, 24u);
    EXPECT_EQ(r.padLength, 2u);
    EXPECT_EQ(r.icvLength, 12u);
    r = inspect(kEspUdp);
    EXPECT_TRUE(r.plaintext);
    EXPECT_EQ(r.nextHeader, 17);
    EXPECT_EQ(r.payloadLength, 13u);
    EXPECT_EQ(r.padLength, 1u);
    EXPECT_EQ(r.icvLength, 16u);
    r = inspect(kEspTunnel);
    EXPECT_TRUE(r.plaintext);
    EXPECT_EQ(r.nextHeader, 4);
    EXPECT_EQ(r.payloadLength, 32u);
    EXPECT_EQ(r.padLength, 2u);
    EXPECT_EQ(r.icvLength, 12u);
}

TEST(EspNull, AnythingThatBreaksTheLayoutIsNotPlaintext) {
    auto expectEncrypted = [](Bytes b, const char *what) { EXPECT_FALSE(inspect(b).plaintext) << what; };
    Bytes b = kEspTcp;
    b[32] = 0x09; expectEncrypted(b, "padding bytes are not 1, 2");
    b = kEspTcp; b[34] = 0x03; expectEncrypted(b, "pad length 3 does not align the trailer");
    b = kEspTcp; b[35] = 59; expectEncrypted(b, "next header 'none'");
    b = kEspTcp; b[35] = 99; expectEncrypted(b, "unknown next header");
    b = kEspTcp; b[20] = 0x40; expectEncrypted(b, "TCP data offset below 5");
    b = kEspTcp; b[21] = 0x03; expectEncrypted(b, "TCP SYN + FIN");
    b = kEspTcp; b[21] = 0x00; expectEncrypted(b, "TCP without flags");
    b = kEspTcp; b[20] = 0x54; expectEncrypted(b, "TCP reserved bit");
    b = kEspTcp; b[26] = 0x01; expectEncrypted(b, "urgent pointer without URG");
    b = kEspTcp; b.push_back(0); expectEncrypted(b, "one byte too long");
    b = kEspTcp; b.pop_back(); expectEncrypted(b, "one byte too short");
    b = kEspUdp; b[13] = 0x0e; expectEncrypted(b, "UDP length field");
    b = kEspTunnel; b[19] ^= 1; expectEncrypted(b, "inner IPv4 header checksum");
    b = kEspTunnel; b[11] = 0x21; expectEncrypted(b, "inner total length");
    // the ICMP message inside the tunnel is not examined (only the IPv4 header is): a damaged checksum there is still a plaintext packet
    b = kEspTunnel; b[30] ^= 1; EXPECT_TRUE(inspect(b).plaintext);
    b = kEspUdp; b[14] = 0x01; EXPECT_TRUE(inspect(b).plaintext) << "the UDP checksum is not examined (offload leaves it empty or unfinished)";
    b = kEspUdp; b[8] = 0; b[9] = 0; b[10] = 0; b[11] = 0; expectEncrypted(b, "UDP with both ports 0");
    b = kEspTcp; b[21] = 0x20; expectEncrypted(b, "URG alone");
    // a prefix of a good packet is not a packet
    for (size_t n = 0; n < kEspTcp.size(); ++n) {
        EXPECT_FALSE(dissect::inspectEspNull(kEspTcp.data() + 8, n > 8 ? n - 8 : 0).plaintext) << n;
    }
}

// Random bytes - what cipher text looks like - must not come out as plaintext. Seeded, 3 million samples of random sizes.
TEST(EspNull, RandomCipherTextStaysEncrypted) {
    // 3 million samples of random size: the first version of the TCP check (any flags, urgent pointer only without URG) accepted one
    // (a TCP header with URG set at offset 14); it was tightened to the usual flag combinations and a zero urgent pointer.
    std::mt19937_64 rng(0x4303'2410ull);
    size_t accepted = 0;
    constexpr size_t kSamples = 3000000;
    Bytes buffer(1600);
    for (size_t i = 0; i < kSamples; ++i) {
        const size_t size = 8 + rng() % 1500;            // the ESP payload after the sequence number: any length
        for (size_t k = 0; k < size; k += 8) { const uint64_t v = rng(); for (size_t j = 0; j < 8 && k + j < size; ++j) buffer[k + j] = static_cast<uint8_t>(v >> (8 * j)); }
        if (dissect::inspectEspNull(buffer.data(), size).plaintext) ++accepted;
    }
    EXPECT_EQ(accepted, 0u) << accepted << " of " << kSamples << " random buffers were taken for ESP-NULL";
}

// The worst case: the random bytes carry a trailer that is right (aligned, no or minimal padding, a known next header). Only the
// check of the payload itself is left; it must stay rare (these rates are not the false positive rate of real traffic, which
// first has to produce such a trailer at random: see RandomCipherTextStaysEncrypted).
TEST(EspNull, PayloadChecksAreStrictEvenWithAPerfectTrailer) {
    std::mt19937_64 rng(0x2410ull);
    struct Case { uint8_t next; size_t maxRate; const char *name; } cases[] = {
        {6, 5, "TCP"}, {17, 60, "UDP"}, {4, 5, "IPv4"}, {41, 5, "IPv6"}, {1, 5, "ICMP"}, {58, 0, "ICMPv6 (not recognised at all)"}};
    constexpr size_t kSamples = 400000;   // maxRate: accepted per million
    for (const auto &c: cases) {
        size_t accepted = 0;
        for (size_t i = 0; i < kSamples; ++i) {
            const size_t payload = 20 + (rng() % 300) / 4 * 4 + 4;   // payload + 2 (trailer) + 12 ICV: pad 2 -> multiple of 4
            Bytes b(payload + 4 + 12);
            for (auto &x: b) x = static_cast<uint8_t>(rng());
            b[payload] = 1; b[payload + 1] = 2; b[payload + 2] = 2; b[payload + 3] = c.next;
            if (dissect::inspectEspNull(b.data(), b.size()).plaintext) ++accepted;
        }
        EXPECT_LE(accepted * 1000000 / kSamples, c.maxRate) << c.name << ": " << accepted << " of " << kSamples;
    }
}

TEST(EspNull, IsOffByDefaultAndTheDissectorDecodesThePayloadWhenOn) {
    const Bytes frame = ipFrame(kEspTcp);
    // default: the payload of an ESP packet is encrypted, whatever it looks like
    const auto off = decode(frame, false);
    EXPECT_EQ(off.p.protocol, "ESP");
    EXPECT_NE(off.p.info.find("Encrypted payload"), std::string::npos);
    EXPECT_TRUE(off.matches("esp && esp.spi == 0x1001 && esp.sequence == 5 && !esp.null && !tcp"));

    const auto on = decode(frame, true);
    EXPECT_EQ(on.p.protocol, "TCP");
    EXPECT_EQ(on.p.src_port, 80);
    EXPECT_EQ(on.p.dst_port, 12345);
    EXPECT_TRUE(on.p.has_esp);
    EXPECT_EQ(on.p.ip_protocol, 6);
    EXPECT_EQ(on.p.tcp_len, 4u);   // the 4 data bytes: pad and ICV are not payload
    EXPECT_TRUE(on.matches("esp && esp.spi == 0x1001 && esp.sequence == 5 && esp.null && tcp.dstport == 12345 && tcp.flags.syn"));
    EXPECT_TRUE(treeHas(on.p, "ESP-NULL heuristic"));
    EXPECT_TRUE(treeHas(on.p, "Pad Length: 2"));
    EXPECT_TRUE(treeHas(on.p, "Integrity Check Value (ICV): 12 bytes"));
    EXPECT_TRUE(treeHas(on.p, "Transmission Control Protocol"));
    EXPECT_TRUE(on.p.info.find("[SYN]") != std::string::npos || on.p.info.find("SYN") != std::string::npos) << on.p.info;
    framesweep::expectInside(on.p, frame.size(), "esp-null tcp");
    // the summary pass reaches the same verdict as the full pass
    const auto summary = decode(frame, true, dissect::ParseMode::Summary);
    EXPECT_EQ(summary.p.protocol, on.p.protocol);
    EXPECT_EQ(summary.p.info, on.p.info);
    EXPECT_EQ(summary.table.find(1)->flags, packet::IpsecTable::kEsp | packet::IpsecTable::kEspPlaintext);

    const auto udp = decode(ipFrame(kEspUdp), true);
    EXPECT_EQ(udp.p.protocol, "UDP");
    EXPECT_TRUE(udp.matches("esp.null && udp.dstport == 5000"));
    EXPECT_TRUE(treeHas(udp.p, "Integrity Check Value (ICV): 16 bytes"));

    const auto tunnel = decode(ipFrame(kEspTunnel), true);
    EXPECT_EQ(tunnel.p.protocol, "ICMP");
    EXPECT_TRUE(tunnel.matches("esp.null && esp.spi == 0x1003"));
    EXPECT_TRUE(treeHas(tunnel.p, "Src: 192.168.0.1"));
    framesweep::expectInside(tunnel.p, ipFrame(kEspTunnel).size(), "esp-null tunnel");
}

TEST(EspNull, CipherTextStaysEncryptedWithTheSettingOn) {
    std::mt19937_64 rng(77);
    Bytes esp = {0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x09};
    for (int i = 0; i < 64; ++i) esp.push_back(static_cast<uint8_t>(rng()));
    const auto d = decode(ipFrame(esp), true);
    EXPECT_EQ(d.p.protocol, "ESP");
    EXPECT_NE(d.p.info.find("Encrypted payload"), std::string::npos);
    EXPECT_TRUE(d.matches("esp.spi == 0x2001 && !esp.null"));
    EXPECT_TRUE(treeHas(d.p, "does not look like an unencrypted ESP-NULL packet"));
    EXPECT_TRUE(treeHas(d.p, "Encrypted Data and Authentication (64 bytes)"));
    // a packet the heuristic is not told about has no such note
    EXPECT_FALSE(treeHas(decode(ipFrame(esp), false).p, "ESP-NULL heuristic"));
}

TEST(EspNull, EspInUdpOnPort4500AndTheHierarchy) {
    const Bytes frame = framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(4500, 4500, kEspTcp)));
    const auto d = decode(frame, true);
    EXPECT_EQ(d.p.protocol, "TCP");
    EXPECT_TRUE(d.matches("esp.null && esp.spi == 0x1001"));
    framesweep::expectInside(d.p, frame.size(), "esp-null in udp");
    // the encrypted ones: UDP is the transport, ESP the layer above it
    Bytes ciphertext = {0x00, 0x00, 0x20, 0x01, 0, 0, 0, 1};
    for (int i = 0; i < 32; ++i) ciphertext.push_back(static_cast<uint8_t>(i * 7 + 3));
    std::vector<packet::PacketInfo> packets = {decode(ipFrame(ciphertext), true).p, decode(ipFrame(kEspTcp), true).p,
                                                decode(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(4500, 4500, ciphertext))), true).p};
    for (auto &p: packets) p.frame_length = 100;
    const auto root = stats::protocolHierarchy(packets, nullptr);
    const auto *ipv4 = hierarchyNode(root, "Internet Protocol Version 4");
    ASSERT_NE(ipv4, nullptr);
    const auto *esp = hierarchyNode(*ipv4, "Encapsulating Security Payload");
    ASSERT_NE(esp, nullptr);
    EXPECT_EQ(esp->packets, 2u);   // the encrypted one and the ESP-NULL TCP one
    EXPECT_NE(hierarchyNode(*esp, "Transmission Control Protocol"), nullptr);
    const auto *udp = hierarchyNode(*ipv4, "User Datagram Protocol");
    ASSERT_NE(udp, nullptr);
    EXPECT_NE(hierarchyNode(*udp, "Encapsulating Security Payload"), nullptr);
}

// Rule 4: the load pass decides, the detail view follows - also when the setting differs by then
TEST(EspNull, TheDetailViewFollowsTheLoadPass) {
    const std::vector<std::vector<char>> frames = {
        std::vector<char>(ipFrame(kEspTcp).begin(), ipFrame(kEspTcp).end())};
    const std::string path = support::writeTemp("esp_null.pcap", support::pcapBytes(frames));
    core::FileProcessor fp;
    fp.sessions().setEspNullHeuristic(true);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_EQ(packets[0].protocol, "TCP");
    fp.sessions().setEspNullHeuristic(false);   // changed afterwards
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[0], details, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
    EXPECT_EQ(details.protocol, "TCP");
    EXPECT_EQ(details.info, packets[0].info);
    EXPECT_TRUE(treeHas(details, "Transmission Control Protocol"));
    EXPECT_TRUE(treeHas(details, "Pad Length: 2"));
    framesweep::expectInside(details, details.raw_data.size(), "details");
    // loaded with the setting off, the same packet is encrypted in both views
    core::FileProcessor off;
    packets.clear();
    ASSERT_TRUE(off.processPcapFile(path, packets, message)) << message;
    EXPECT_EQ(packets[0].protocol, "ESP");
    packet::PacketInfo offDetails;
    off.sessions().setEspNullHeuristic(true);   // changed afterwards
    ASSERT_TRUE(core::buildPacketDetails(path, packets[0], offDetails, &packets, &off.captureInfo(), nullptr, &off.sessions()));
    EXPECT_EQ(offDetails.protocol, "ESP");
    std::remove(path.c_str());
}

TEST(EspNull, SweepsStayInsideTheFrame) {
    framesweep::sweep(ipFrame(kEspTcp), 0x4303'0001u, 400, 1, true);
    framesweep::sweep(ipFrame(kEspUdp), 0x4303'0002u, 400, 1, true);
    framesweep::sweep(ipFrame(kEspTunnel), 0x4303'0003u, 400, 1, true);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(4500, 4500, kEspTunnel))), 0x4303'0004u, 400, 1, true);
}

TEST(EspNull, TheSettingSurvivesARestartAndDefaultsToOff) {
    const auto dir = std::filesystem::temp_directory_path() / "imshark_esp_null_settings";
    const std::string path = (dir / "settings.ini").string();
    ui::Settings s;
    EXPECT_FALSE(s.espNullHeuristic);
    EXPECT_FALSE(ui::loadSettings(path).espNullHeuristic);
    s.espNullHeuristic = true;
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_TRUE(ui::loadSettings(path).espNullHeuristic);
    s.espNullHeuristic = false;
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_FALSE(ui::loadSettings(path).espNullHeuristic);
    std::filesystem::remove_all(dir);
    // the session tables keep the setting when a new capture clears them
    dissect::SessionTables tables;
    EXPECT_FALSE(tables.espNullHeuristic());
    tables.setEspNullHeuristic(true);
    tables.clear();
    EXPECT_TRUE(tables.espNullHeuristic());
}

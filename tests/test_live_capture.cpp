#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <capture/live_capture.h>
#include <core.h>

#include "support.h"

using support::hex;

namespace {
    // Ethernet + IPv4 fragment of `payload[offset, offset+len)`; the real offset field is in 8-byte units
    std::vector<char> fragment(const std::vector<char> &payload, size_t offset, size_t len, uint16_t id, bool more) {
        char head[160];
        const uint16_t field = static_cast<uint16_t>((more ? 0x2000 : 0) | (offset / 8));
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 0800 4500%04zx %04x %04x 40110000 0a000001 0a000002", 20 + len, id, field);
        auto frame = hex(head);
        frame.insert(frame.end(), payload.begin() + static_cast<long>(offset), payload.begin() + static_cast<long>(offset + len));
        return frame;
    }

    std::vector<char> seg(uint32_t seq, const std::string &data, const char *flags = "18") {
        char s[16];
        std::snprintf(s, sizeof s, "%08x", seq);
        return support::tcpPacket("0a000001", "0a000002", "c350", "0050", s, "00000001", flags, data);
    }

    /// A mixed Ethernet capture: ARP, a TCP handshake start, an HTTP request split over two segments (reassembly annotates
    /// the first segment when the second arrives), a DNS query in three IP fragments, a plain UDP datagram and a runt frame.
    std::vector<std::vector<char>> traffic() {
        const std::string request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        const auto dns = hex("c350 0035 0025 0000 1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001");
        return {
            hex(support::kArpRequest),
            seg(999, "", "02"),
            seg(1000, request.substr(0, 20)),
            hex(support::kEthIpUdp),
            fragment(dns, 0, 16, 0x4242, true),
            seg(1020, request.substr(20)),
            fragment(dns, 16, 16, 0x4242, true),
            fragment(dns, 32, 5, 0x4242, false),
            hex("001122334455 aabbccddeeff 88b5 de ad be ef"),    // unknown EtherType
            hex("0011223344"),                                      // shorter than an Ethernet header
        };
    }

    void inject(capture::LiveCapture &live, const std::vector<std::vector<char>> &frames, size_t from, size_t to) {
        for (size_t i = from; i < to; ++i) {
            ASSERT_TRUE(live.injectPacket(1700000000 + i / 1000, static_cast<uint32_t>((i % 1000) * 1000 + 7), frames[i])) << live.lastError();
        }
    }

    // Everything the loader derives for one packet, field by field (PacketInfo has no operator==)
    void expectSameSummary(const packet::PacketInfo &a, const packet::PacketInfo &b, size_t i) {
        SCOPED_TRACE("packet " + std::to_string(i + 1));
        EXPECT_EQ(a.number, b.number);
        EXPECT_EQ(a.time, b.time);
        EXPECT_EQ(a.file_offset, b.file_offset);
        EXPECT_EQ(a.link_type, b.link_type);
        EXPECT_EQ(a.captured_length, b.captured_length);
        EXPECT_EQ(a.frame_length, b.frame_length);
        EXPECT_EQ(a.length, b.length);
        EXPECT_EQ(a.source, b.source);
        EXPECT_EQ(a.destination, b.destination);
        EXPECT_EQ(a.protocol, b.protocol);
        EXPECT_EQ(a.info, b.info);
        EXPECT_EQ(a.app_text, b.app_text);
        EXPECT_EQ(a.app_text2, b.app_text2);
        EXPECT_EQ(a.vlan_ids, b.vlan_ids);
        EXPECT_EQ(a.tcp_relative_seq, b.tcp_relative_seq);
        EXPECT_EQ(a.tcp_relative_ack, b.tcp_relative_ack);
        EXPECT_EQ(a.tcp_pdu_start, b.tcp_pdu_start);
        EXPECT_EQ(a.tcp_pdu_len, b.tcp_pdu_len);
        EXPECT_EQ(a.tcp_reassembled_in, b.tcp_reassembled_in);
        EXPECT_EQ(a.tcp_len, b.tcp_len);
        EXPECT_EQ(a.reassembled_in, b.reassembled_in);
        EXPECT_EQ(a.payload_offset, b.payload_offset);
        EXPECT_EQ(a.payload_length, b.payload_length);
        EXPECT_EQ(a.ip_id, b.ip_id);
        EXPECT_EQ(a.tcp_analysis, b.tcp_analysis);
        EXPECT_EQ(a.ether_type, b.ether_type);
        EXPECT_EQ(a.src_port, b.src_port);
        EXPECT_EQ(a.dst_port, b.dst_port);
        EXPECT_EQ(a.app_type, b.app_type);
        EXPECT_EQ(a.app_flags, b.app_flags);
        EXPECT_EQ(a.app_code, b.app_code);
        EXPECT_EQ(a.tcp_dup_ack, b.tcp_dup_ack);
        EXPECT_EQ(a.ip_protocol, b.ip_protocol);
        EXPECT_EQ(a.ttl, b.ttl);
        EXPECT_EQ(a.tcp_flags, b.tcp_flags);
        EXPECT_EQ(a.l2_size, b.l2_size);
        EXPECT_EQ(a.checksum_state, b.checksum_state);
        EXPECT_EQ(a.tcp_pdu_state, b.tcp_pdu_state);
        EXPECT_EQ(a.ip_frag, b.ip_frag);
        EXPECT_EQ(a.ip_version, b.ip_version);
    }

    // The oracle: the packets of the finished temp file loaded by the ordinary file loader
    void expectMatchesFileLoad(capture::LiveCapture &live, const core::FileProcessor &liveProcessor,
                               const std::vector<packet::PacketInfo> &livePackets) {
        std::vector<packet::PacketInfo> loaded;
        core::FileProcessor fp;
        std::string message;
        ASSERT_TRUE(fp.processPcapFile(live.tempPath(), loaded, message)) << message;
        EXPECT_TRUE(message.empty()) << message;
        ASSERT_EQ(livePackets.size(), loaded.size());
        for (size_t i = 0; i < loaded.size(); ++i) expectSameSummary(livePackets[i], loaded[i], i);
        EXPECT_EQ(liveProcessor.captureStartEpoch(), fp.captureStartEpoch());
        ASSERT_EQ(liveProcessor.captureInfo().interfaces.size(), 1u);
        EXPECT_EQ(liveProcessor.captureInfo().interfaces[0].packets, fp.captureInfo().interfaces[0].packets);
        EXPECT_EQ(liveProcessor.captureInfo().interfaces[0].linkType, fp.captureInfo().interfaces[0].linkType);
        EXPECT_EQ(liveProcessor.captureInfo().fileSize, fp.captureInfo().fileSize);
    }

    uint32_t le32(const std::string &bytes, size_t at) {
        uint32_t v = 0;
        for (int i = 3; i >= 0; --i) v = (v << 8) | static_cast<unsigned char>(bytes[at + static_cast<size_t>(i)]);
        return v;
    }

    std::string slurp(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
} // namespace

// ---- capture filter ----------------------------------------------------------------------------------------

TEST(LiveCaptureFilter, ValidAndInvalidExpressions) {
    if (!capture::liveCaptureAvailable()) GTEST_SKIP() << "built without libpcap";
    for (const char *ok: {"", "tcp", "tcp port 80", "host 10.0.0.1 and not udp", "ip6 or arp", "ether src 00:11:22:33:44:55",
                          "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0", "vlan 100 and net 192.168.0.0/16"}) {
        const auto check = capture::validateCaptureFilter(ok);
        EXPECT_TRUE(check.ok) << ok << ": " << check.error;
        EXPECT_TRUE(check.error.empty()) << ok;
    }
    for (const char *bad: {"tcp port", "tcp port (", "foo bar baz", "host", "tcp and and udp", "port 99999", "ip proto notaprotocol"}) {
        const auto check = capture::validateCaptureFilter(bad);
        EXPECT_FALSE(check.ok) << bad;
        EXPECT_FALSE(check.error.empty()) << bad;
    }
    // other link types and snaplens compile too (raw IP has no Ethernet header: "ether" is not valid there)
    EXPECT_TRUE(capture::validateCaptureFilter("udp port 53", 101, 96).ok);
    EXPECT_TRUE(capture::validateCaptureFilter("udp port 53", 0, 65535).ok);
    EXPECT_FALSE(capture::validateCaptureFilter("ether host 00:11:22:33:44:55", 101).ok);
}

TEST(LiveCaptureStub, ReportsNotAvailable) {
    if (capture::liveCaptureAvailable()) GTEST_SKIP() << "libpcap is available";
    const auto list = capture::listInterfaces();
    EXPECT_TRUE(list.interfaces.empty());
    EXPECT_EQ(list.error, capture::kNotAvailable);
    const auto check = capture::validateCaptureFilter("tcp");
    EXPECT_FALSE(check.ok);
    EXPECT_EQ(check.error, capture::kNotAvailable);

    capture::LiveCapture live;
    capture::CaptureOptions options;
    options.interfaceName = "lo0";
    EXPECT_FALSE(live.start(options));
    EXPECT_FALSE(live.running());
    EXPECT_EQ(live.lastError(), capture::kNotAvailable);
    live.stop();
    live.stop();
}

// ---- interfaces and starting -------------------------------------------------------------------------------

TEST(LiveCaptureInterfaces, ListingDoesNotCrashAndIsConsistent) {
    const auto list = capture::listInterfaces();
    if (!capture::liveCaptureAvailable()) {
        EXPECT_FALSE(list.error.empty());
        return;
    }
    for (const auto &itf: list.interfaces) {
        EXPECT_FALSE(itf.name.empty());
        if (itf.loopback) EXPECT_TRUE(itf.up || !itf.running) << itf.name;
    }
    if (list.error.empty() && list.interfaces.empty()) GTEST_LOG_(INFO) << "no capture interfaces";
}

TEST(LiveCaptureStart, FailsCleanlyWithoutAUsableInterface) {
    capture::LiveCapture live;
    capture::CaptureOptions options;       // no interface at all
    EXPECT_FALSE(live.start(options));
    EXPECT_FALSE(live.running());
    EXPECT_FALSE(live.lastError().empty());

    options.interfaceName = "imshark-no-such-interface0";
    EXPECT_FALSE(live.start(options));
    EXPECT_FALSE(live.running());
    EXPECT_FALSE(live.lastError().empty());
    EXPECT_TRUE(live.tempPath().empty()) << "no file is created when the device cannot be opened";
    live.stop();
    live.stop();   // idempotent
    std::vector<capture::CapturedPacket> none;
    EXPECT_EQ(live.takePackets(none), 0u);
}

// ---- the injection seam: writer, queue and consumer without privileges ----------------------------------------

TEST(LiveCaptureSeam, IncrementalSummariesEqualTheFileLoad) {
    const auto frames = traffic();
    capture::LiveCapture live;
    ASSERT_TRUE(live.beginInjected(1, 262144)) << live.lastError();
    inject(live, frames, 0, frames.size());
    EXPECT_EQ(live.packetCount(), frames.size());

    core::FileProcessor processor;
    std::vector<packet::PacketInfo> packets;
    EXPECT_EQ(capture::appendCapturedPackets(live, processor, packets), frames.size());
    EXPECT_EQ(capture::appendCapturedPackets(live, processor, packets), 0u) << "nothing new";
    ASSERT_EQ(packets.size(), frames.size());

    // sanity of the oracle itself: the traffic exercises reassembly and the odd frames
    EXPECT_EQ(packets[2].tcp_pdu_state, 4) << packets[2].info;
    EXPECT_EQ(packets[2].tcp_reassembled_in, 6u);
    EXPECT_NE(packets[2].info.find("[Reassembled in #6]"), std::string::npos) << packets[2].info;
    EXPECT_EQ(packets[4].ip_frag, 1);
    EXPECT_EQ(packets[4].reassembled_in, 8u);
    EXPECT_EQ(packets[5].protocol, "HTTP");
    EXPECT_EQ(packets[7].protocol, "DNS");

    expectMatchesFileLoad(live, processor, packets);

    // the details path reads the frame back from the temp file by the offset of the summary
    std::vector<char> bytes;
    for (size_t i = 0; i < frames.size(); ++i) {
        ASSERT_TRUE(core::readPacketBytes(live.tempPath(), packets[i], bytes)) << i;
        EXPECT_EQ(bytes, frames[i]) << i;
    }
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(live.tempPath(), packets[7], details, &packets, &processor.captureInfo(), nullptr, &processor.sessions()));
    EXPECT_FALSE(details.fields.empty());
}

TEST(LiveCaptureSeam, BatchesPolledWhileCapturingEqualTheFileLoad) {
    const auto frames = traffic();
    capture::LiveCapture live;
    ASSERT_TRUE(live.beginInjected(1, 262144)) << live.lastError();
    core::FileProcessor processor;
    std::vector<packet::PacketInfo> packets;

    // 3 + 1 + 4 + 2: the HTTP request completes (packet 6) and the fragments complete (packet 8) in later polls than their
    // first parts, so earlier summaries are annotated after they were already handed out
    size_t done = 0, appended = 0;
    for (size_t n: {3, 1, 4, 2}) {
        inject(live, frames, done, done + n);
        done += n;
        appended += capture::appendCapturedPackets(live, processor, packets);
        EXPECT_EQ(packets.size(), done);
    }
    EXPECT_EQ(appended, frames.size());
    expectMatchesFileLoad(live, processor, packets);

    // after stop() the file is complete and still readable; stop() twice is harmless
    live.stop();
    live.stop();
    EXPECT_FALSE(live.running());
    expectMatchesFileLoad(live, processor, packets);
    EXPECT_FALSE(live.injectPacket(1, 1, frames[0])) << "the file is closed";
}

TEST(LiveCaptureSeam, ProducerThreadAndPollingConsumer) {
    const auto frames = traffic();
    capture::LiveCapture live;
    ASSERT_TRUE(live.beginInjected(1, 262144)) << live.lastError();
    constexpr size_t kRounds = 40;     // the sample capture over and over: 400 packets
    const size_t total = kRounds * frames.size();

    std::thread producer([&] {
        for (size_t i = 0; i < total; ++i) {
            live.injectPacket(1700000000 + i / 1000, static_cast<uint32_t>((i % 1000) * 1000), frames[i % frames.size()]);
            if (i % 37 == 0) std::this_thread::yield();
        }
    });

    core::FileProcessor processor;
    std::vector<packet::PacketInfo> packets;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (packets.size() < total && std::chrono::steady_clock::now() < deadline) {
        capture::appendCapturedPackets(live, processor, packets);
        (void) live.packetCount();
        (void) live.lastError();
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    producer.join();
    capture::appendCapturedPackets(live, processor, packets);
    ASSERT_EQ(packets.size(), total);
    live.stop();
    expectMatchesFileLoad(live, processor, packets);
}

TEST(LiveCaptureSeam, TempFileIsAClassicPcapWithTheDocumentedLayout) {
    capture::LiveCapture live;
    ASSERT_TRUE(live.beginInjected(113, 100)) << live.lastError();   // Linux cooked, snaplen 100
    const std::vector<char> small = hex("00010203 04050607 08090a0b");
    std::vector<char> big(300);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>(i);
    ASSERT_TRUE(live.injectPacket(1700000001, 123456, small));
    ASSERT_TRUE(live.injectPacket(1700000002, 999999, big));          // truncated to the snaplen, wire length kept
    ASSERT_TRUE(live.injectPacket(1700000003, 0, small, 2000));       // an explicit wire length
    live.stop();

    std::vector<capture::CapturedPacket> queued;
    ASSERT_EQ(live.takePackets(queued), 3u);
    EXPECT_EQ(live.takePackets(queued), 0u);

    const std::string file = slurp(live.tempPath());
    ASSERT_EQ(file.size(), 24u + 3 * 16 + 12 + 100 + 12);
    // header: magic, 2.4, thiszone, sigfigs, snaplen, linktype - checked byte by byte, not through the loader
    EXPECT_EQ(le32(file, 0), 0xa1b2c3d4u);
    EXPECT_EQ(static_cast<unsigned char>(file[4]) | (static_cast<unsigned char>(file[5]) << 8), 2);
    EXPECT_EQ(static_cast<unsigned char>(file[6]) | (static_cast<unsigned char>(file[7]) << 8), 4);
    EXPECT_EQ(le32(file, 8), 0u);
    EXPECT_EQ(le32(file, 12), 0u);
    EXPECT_EQ(le32(file, 16), 100u);
    EXPECT_EQ(le32(file, 20), 113u);
    // record 1
    EXPECT_EQ(le32(file, 24), 1700000001u);
    EXPECT_EQ(le32(file, 28), 123456u);
    EXPECT_EQ(le32(file, 32), 12u);
    EXPECT_EQ(le32(file, 36), 12u);
    EXPECT_EQ(file.substr(40, 12), std::string(small.begin(), small.end()));
    // record 2: 100 captured of 300 on the wire
    EXPECT_EQ(le32(file, 52), 1700000002u);
    EXPECT_EQ(le32(file, 56), 999999u);
    EXPECT_EQ(le32(file, 60), 100u);
    EXPECT_EQ(le32(file, 64), 300u);
    EXPECT_EQ(file.substr(68, 100), std::string(big.begin(), big.begin() + 100));
    // record 3
    EXPECT_EQ(le32(file, 168), 1700000003u);
    EXPECT_EQ(le32(file, 176), 12u);
    EXPECT_EQ(le32(file, 180), 2000u);

    // the queue carries the same facts as the file
    EXPECT_EQ(queued[0].fileOffset, 40u);
    EXPECT_EQ(queued[0].capturedLength, 12u);
    EXPECT_EQ(queued[0].tsMicros, 123456u);
    EXPECT_EQ(queued[0].linkType, 113u);
    EXPECT_EQ(queued[1].fileOffset, 68u);
    EXPECT_EQ(queued[1].capturedLength, 100u);
    EXPECT_EQ(queued[1].originalLength, 300u);
    EXPECT_EQ(queued[2].fileOffset, 184u);
    EXPECT_EQ(queued[2].originalLength, 2000u);

    // an optional copy for an independent check (e.g. with Python's struct module): IMSHARK_LIVE_KEEP=/path/to/copy.pcap
    if (const char *keep = std::getenv("IMSHARK_LIVE_KEEP")) std::filesystem::copy_file(live.tempPath(), keep, std::filesystem::copy_options::overwrite_existing);
}

TEST(LiveCaptureSeam, TempFileLifetime) {
    std::string kept, removed;
    {
        capture::LiveCapture live;
        ASSERT_TRUE(live.beginInjected(1, 65535));
        removed = live.tempPath();
        EXPECT_TRUE(std::filesystem::exists(removed));
    }
    EXPECT_FALSE(std::filesystem::exists(removed)) << "the destructor removes an unreleased file";

    {
        capture::LiveCapture live;
        ASSERT_TRUE(live.beginInjected(1, 65535));
        kept = live.releaseTempFile();
        EXPECT_EQ(kept, live.tempPath());
    }
    EXPECT_TRUE(std::filesystem::exists(kept)) << "a released file belongs to the caller";
    std::error_code ec;
    std::filesystem::remove(kept, ec);

    // starting a new session removes the file of the previous one
    capture::LiveCapture live;
    ASSERT_TRUE(live.beginInjected(1, 65535));
    const std::string first = live.tempPath();
    ASSERT_TRUE(live.beginInjected(1, 65535));
    EXPECT_NE(first, live.tempPath());
    EXPECT_FALSE(std::filesystem::exists(first));
    EXPECT_TRUE(std::filesystem::exists(live.tempPath()));
}

// ---- a real capture on the loopback interface (skipped without the privilege) --------------------------------

#ifndef _WIN32
TEST(LiveCaptureDevice, LoopbackUdpDatagram) {
    if (!capture::liveCaptureAvailable()) GTEST_SKIP() << "built without libpcap";
    const auto list = capture::listInterfaces();
    std::string loopback;
    for (const auto &itf: list.interfaces) {
        if (itf.loopback && itf.up) { loopback = itf.name; break; }
    }
    if (loopback.empty()) GTEST_SKIP() << "no loopback interface";

    // pick a free UDP port first, so that the BPF filter selects exactly our datagrams
    int receiver = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(receiver, reinterpret_cast<sockaddr *>(&addr), sizeof addr), 0);
    socklen_t len = sizeof addr;
    ASSERT_EQ(::getsockname(receiver, reinterpret_cast<sockaddr *>(&addr), &len), 0);
    const unsigned port = ntohs(addr.sin_port);

    capture::LiveCapture live;
    capture::CaptureOptions options;
    options.interfaceName = loopback;
    options.filter = "udp and port " + std::to_string(port);
    options.promiscuous = false;
    if (!live.start(options)) {
        ::close(receiver);
        if (live.lastError().rfind("Permission denied", 0) == 0) GTEST_SKIP() << live.lastError();
        FAIL() << live.lastError();
    }
    EXPECT_TRUE(live.running());
    EXPECT_TRUE(std::filesystem::exists(live.tempPath()));

    const std::string payload = "imshark live capture test";
    int sender = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (live.packetCount() == 0 && std::chrono::steady_clock::now() < deadline) {
        ::sendto(sender, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr *>(&addr), sizeof addr);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ::close(sender);
    ::close(receiver);
    live.stop();
    EXPECT_FALSE(live.running());
    ASSERT_GE(live.packetCount(), 1u) << live.lastError();
    EXPECT_TRUE(live.lastError().empty()) << live.lastError();

    core::FileProcessor processor;
    std::vector<packet::PacketInfo> packets;
    EXPECT_EQ(capture::appendCapturedPackets(live, processor, packets), live.packetCount());
    ASSERT_FALSE(packets.empty());
    for (const auto &p: packets) {
        EXPECT_EQ(p.protocol, "UDP") << p.info;
        EXPECT_EQ(p.dst_port, port);
        EXPECT_EQ(p.payload_length, payload.size());
    }
    expectMatchesFileLoad(live, processor, packets);
}
#endif

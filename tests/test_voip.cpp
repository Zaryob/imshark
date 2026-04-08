#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/voip.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

std::vector<char> makeUdpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &udpPayload) {
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };

    size_t ipTotalLen = 20 + 8 + udpPayload.size();
    std::vector<uint8_t> ip = {
        0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x00, 0x01, 0x00, 0x00,
        64, 17, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };

    uint32_t csum = 0;
    for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ip[10] = static_cast<uint8_t>(folded >> 8);
    ip[11] = static_cast<uint8_t>(folded & 0xff);

    size_t udpLen = 8 + udpPayload.size();
    std::vector<uint8_t> udp = {
        static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
        static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
        static_cast<uint8_t>(udpLen >> 8), static_cast<uint8_t>(udpLen & 0xff),
        0, 0 // UDP checksum 0
    };

    frame.insert(frame.end(), ip.begin(), ip.end());
    frame.insert(frame.end(), udp.begin(), udp.end());
    frame.insert(frame.end(), udpPayload.begin(), udpPayload.end());

    std::vector<char> out(frame.size());
    std::memcpy(out.data(), frame.data(), frame.size());
    return out;
}

} // namespace

TEST(Voip, SipInviteRequestWithSdp) {
    std::string sipMsg =
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
        "Max-Forwards: 70\r\n"
        "To: Bob <sip:bob@biloxi.com>\r\n"
        "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n";

    std::vector<uint8_t> pdu(sipMsg.begin(), sipMsg.end());
    auto pkt = parse(makeUdpPacket(5060, 5060, pdu));

    EXPECT_EQ(pkt.protocol, "SIP");
    EXPECT_NE(pkt.info.find("INVITE sip:bob@biloxi.com"), std::string::npos);
    EXPECT_NE(pkt.info.find("314159 INVITE"), std::string::npos);
    EXPECT_EQ(pkt.app_text, "a84b4c76e66710@pc33.atlanta.com");
}

TEST(Voip, RtpDissection) {
    // RTP Header (12 bytes)
    // V=2, P=0, X=0, CC=0 -> 0x80
    // M=1, PT=0 (PCMU) -> 0x80
    // Seq: 1234 -> 0x04D2
    // TS: 160 -> 0x000000A0
    // SSRC: 0x11223344
    std::vector<uint8_t> pdu = {
        0x80, 0x80,
        0x04, 0xd2,
        0x00, 0x00, 0x00, 0xa0,
        0x11, 0x22, 0x33, 0x44,
        // 4 bytes payload
        1, 2, 3, 4
    };

    packet::PacketInfo pkt(1);
    network::TCPConnection conn;
    dissect::Context ctx{pkt, reinterpret_cast<const char *>(pdu.data()), pdu.size(),
                         conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtp(ctx, reinterpret_cast<const char *>(pdu.data()), pdu.size());

    EXPECT_EQ(pkt.protocol, "RTP");
    EXPECT_EQ(pkt.app_type, 0); // PCMU
    EXPECT_NE(pkt.info.find("PT=0"), std::string::npos);
    EXPECT_NE(pkt.info.find("SSeq=1234"), std::string::npos);
    EXPECT_NE(pkt.info.find("0x11223344"), std::string::npos);
}

TEST(Voip, RtcpSenderReport) {
    // RTCP Header (8 bytes)
    // V=2, P=0, RC=0 -> 0x80
    // PT=200 (SR) -> 0xC8
    // Length: 1 (2 32-bit words total = 8 bytes) -> 0x0001
    // SSRC: 0x55667788
    std::vector<uint8_t> pdu = {
        0x80, 0xc8,
        0x00, 0x01,
        0x55, 0x66, 0x77, 0x88
    };

    packet::PacketInfo pkt(1);
    network::TCPConnection conn;
    dissect::Context ctx{pkt, reinterpret_cast<const char *>(pdu.data()), pdu.size(),
                         conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtcp(ctx, reinterpret_cast<const char *>(pdu.data()), pdu.size());

    EXPECT_EQ(pkt.protocol, "RTCP");
    EXPECT_EQ(pkt.app_type, 200);
    EXPECT_NE(pkt.info.find("Sender Report (SR)"), std::string::npos);
    EXPECT_NE(pkt.info.find("0x55667788"), std::string::npos);
}

TEST(Voip, SipStreamFramer) {
    std::string sipMsg =
        "SIP/2.0 200 OK\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";

    auto f1 = frameSip(sipMsg.data(), 10);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameSip(sipMsg.data(), sipMsg.size() - 2);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameSip(sipMsg.data(), sipMsg.size());
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, sipMsg.size());
}

// ---- R3: framing, validation, header case, sweeps (RFC 3261, RFC 3550, RFC 2326)

#include "frame_sweep.h"

namespace {

using framesweep::Bytes;

Bytes bytesOf(const std::string &s) { return Bytes(s.begin(), s.end()); }

Bytes tcpSegment(uint16_t sport, uint16_t dport, uint32_t seq, const Bytes &payload) {
    Bytes h = {static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff), static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
               static_cast<uint8_t>(seq >> 24), static_cast<uint8_t>(seq >> 16), static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq),
               0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0};
    h.insert(h.end(), payload.begin(), payload.end());
    return h;
}

Bytes sipOverUdp(const std::string &msg, uint16_t port = 5060) {
    return framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(port, port, bytesOf(msg))));
}

Bytes textOverTcp(const std::string &msg, uint16_t port) {
    return framesweep::ethernet(0x0800, framesweep::ipv4Packet(6, tcpSegment(40000, port, 1000, bytesOf(msg))));
}

// RFC 3261 section 24.1 style INVITE, with the compact header forms of section 7.3.3
const std::string kCompactInvite =
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
    "v: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
    "t: Bob <sip:bob@biloxi.com>\r\n"
    "f: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
    "i: a84b4c76e66710@pc33.atlanta.com\r\n"
    "CSeq: 314159 INVITE\r\n"
    "c: application/sdp\r\n"
    "l: 35\r\n"
    "\r\n"
    "v=0\r\n"
    "s=-\r\n"
    "m=audio 49172 RTP/AVP 0\r\n";

const packet::Field *findNode(const std::vector<packet::Field> &nodes, const std::string &prefix) {
    for (const auto &n: nodes) {
        if (n.text.rfind(prefix, 0) == 0) return &n;
        if (auto *c = findNode(n.children, prefix)) return c;
    }
    return nullptr;
}

// Calls a dissector directly on the bytes and checks that every field lies inside them
template<typename Fn>
void directSweep(Fn dissector, const Bytes &msg, uint32_t seed) {
    auto next = [&seed]() { seed = seed * 1664525u + 1013904223u; return seed >> 8; };
    auto run = [&](const Bytes &b) {
        packet::PacketInfo pkt(1);
        network::TCPConnection conn;
        const char *p = reinterpret_cast<const char *>(b.data());
        dissect::Context ctx{pkt, p, b.size(), conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
        dissector(ctx, p, b.size());
        framesweep::expectInside(pkt, b.size(), "direct dissection");
    };
    for (size_t n = 0; n <= msg.size(); ++n) run(Bytes(msg.begin(), msg.begin() + n));
    for (int round = 0; round < 400; ++round) {
        Bytes m = msg;
        for (int i = 0, flips = 1 + int(next() % 3); i < flips; ++i) m[next() % m.size()] = static_cast<uint8_t>(next());
        if (next() % 2) m.resize(next() % (m.size() + 1));
        run(m);
    }
}

} // namespace

TEST(Sip, ContentLengthIsBoundedAndOverflowSafe) {
    auto frame = [](const std::string &cl) {
        const std::string msg = "SIP/2.0 200 OK\r\nContent-Length: " + cl + "\r\n\r\nhello";
        return frameSip(msg.data(), msg.size());
    };
    EXPECT_EQ(frame("5").kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(frame("6").kind, StreamFrame::Kind::NeedMore);
    // 2^64 - 1 used to overflow headerEnd + bodyLen and report a short "complete" frame
    EXPECT_EQ(frame("18446744073709551615").kind, StreamFrame::Kind::Reject);
    EXPECT_EQ(frame("18446744073709551616").kind, StreamFrame::Kind::Reject);
    EXPECT_EQ(frame("4294967296").kind, StreamFrame::Kind::Reject);
    EXPECT_EQ(frame("65536").kind, StreamFrame::Kind::NeedMore) << "the largest accepted body";
    EXPECT_EQ(frame("65537").kind, StreamFrame::Kind::Reject) << "a stream must not wait for more than 64 KiB of body";
    EXPECT_EQ(frame("-1").kind, StreamFrame::Kind::Reject);
    EXPECT_EQ(frame("5x").kind, StreamFrame::Kind::Reject);
}

TEST(Sip, HeaderNamesAreCaseInsensitiveAndMayBeCompact) {
    for (const char *name: {"content-length", "CONTENT-LENGTH", "Content-length", "l", "L"}) {
        const std::string msg = std::string("SIP/2.0 200 OK\r\n") + name + ": 5\r\n\r\nhelloSIP/2.0 180 Ringing\r\n";
        const auto f = frameSip(msg.data(), msg.size());
        EXPECT_EQ(f.kind, StreamFrame::Kind::Complete) << name;
        EXPECT_EQ(f.length, msg.find("SIP/2.0 180")) << name << ": the body is part of the first message";
    }
    // bare LF line ends
    const std::string lf = "SIP/2.0 200 OK\nl: 2\n\nokNEXT";
    EXPECT_EQ(frameSip(lf.data(), lf.size()).length, lf.size() - 4);
    // without a Content-Length there is no body
    const std::string none = "SIP/2.0 200 OK\r\nCSeq: 1 BYE\r\n\r\nSIP/2.0 200 OK\r\n";
    EXPECT_EQ(frameSip(none.data(), none.size()).length, none.find("\r\n\r\n") + 4);
}

TEST(Sip, TextThatIsNotSipOnThePortFallsThrough) {
    for (const std::string &text: {std::string("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), std::string("hello there, this is just text\nmore\n"),
                                  std::string("INVITE\r\nCSeq: 1 INVITE\r\n\r\n"), std::string("INVITE sip:bob SIP/3.0\r\n\r\n"),
                                  std::string("SIP/2.0 2OK Broken\r\n\r\n"), std::string("INVITE  SIP/2.0\r\n\r\n")}) {
        const auto udp = framesweep::parseEthernet(sipOverUdp(text));
        EXPECT_EQ(udp.protocol, "UDP") << text;
        EXPECT_EQ(frameSip(text.data(), text.size()).kind == StreamFrame::Kind::Reject ||
                  frameSip(text.data(), text.size()).kind == StreamFrame::Kind::NeedMore, true) << text;
    }
    EXPECT_EQ(frameSip("GET / HTTP/1.1\r\nHost: x\r\n\r\n", 28).kind, StreamFrame::Kind::Reject);
    // valid request and status lines are SIP
    for (const std::string &line: {std::string("OPTIONS sip:carol@chicago.com SIP/2.0"), std::string("SIP/2.0 486 Busy Here"), std::string("sip/2.0 200 OK"),
                                   std::string("REGISTER sip:registrar.biloxi.com SIP/2.0"), std::string("SIP/2.0 200")}) {
        const auto pkt = framesweep::parseEthernet(sipOverUdp(line + "\r\nCSeq: 1 OPTIONS\r\n\r\n"));
        EXPECT_EQ(pkt.protocol, "SIP") << line;
    }
}

TEST(Sip, CompactFormsAreReadAndSdpIsShown) {
    const auto pkt = framesweep::parseEthernet(sipOverUdp(kCompactInvite));
    EXPECT_EQ(pkt.protocol, "SIP");
    EXPECT_EQ(pkt.app_text, "a84b4c76e66710@pc33.atlanta.com");
    EXPECT_EQ(pkt.info, "INVITE sip:bob@biloxi.com SIP/2.0 | 314159 INVITE");
    ASSERT_NE(findNode(pkt.fields, "Call-ID: a84b4c76e66710@pc33.atlanta.com"), nullptr);
    ASSERT_NE(findNode(pkt.fields, "From: Alice <sip:alice@atlanta.com>;tag=1928301774"), nullptr);
    ASSERT_NE(findNode(pkt.fields, "To: Bob <sip:bob@biloxi.com>"), nullptr);
    // the SDP body starts right after the blank line: 14 + 20 + 8 bytes of Ethernet/IP/UDP in front
    const auto *sdp = findNode(pkt.fields, "Session Description Protocol");
    ASSERT_NE(sdp, nullptr);
    EXPECT_EQ(sdp->offset, 42 + kCompactInvite.find("\r\n\r\n") + 4);
    EXPECT_EQ(sdp->length, 35u);
    ASSERT_NE(findNode(pkt.fields, "m=audio 49172 RTP/AVP 0"), nullptr);
    // LF-only separators work too
    std::string lfMsg = kCompactInvite;
    for (size_t p; (p = lfMsg.find("\r\n")) != std::string::npos;) lfMsg.erase(p, 1);
    const auto lf = framesweep::parseEthernet(sipOverUdp(lfMsg));
    EXPECT_EQ(lf.protocol, "SIP");
    ASSERT_NE(findNode(lf.fields, "Session Description Protocol"), nullptr);
    // header names in any case
    const auto upper = framesweep::parseEthernet(sipOverUdp("SIP/2.0 200 OK\r\nCALL-ID: abc\r\ncseq: 7 BYE\r\n\r\n"));
    EXPECT_EQ(upper.app_text, "abc");
    EXPECT_EQ(upper.info, "SIP/2.0 200 OK | 7 BYE");
}

TEST(Sip, HostileTextIsShownPrintable) {
    const auto pkt = framesweep::parseEthernet(sipOverUdp(std::string("OPTIONS sip:a\x01\x02 SIP/2.0\r\nCall-ID: x\x7f\r\n\r\n")));
    ASSERT_EQ(pkt.protocol, "SIP");
    for (unsigned char c: pkt.info) EXPECT_TRUE(c >= 32 && c < 127);
    for (unsigned char c: pkt.app_text) EXPECT_TRUE(c >= 32 && c < 127);
}

TEST(Sip, TcpMessageSplitOverTwoSegmentsIsFramedByItsContentLength) {
    packet::PacketParser parser;
    auto run = [&](int number, const Bytes &frame) {
        packet::PacketInfo pack(number);
        pack.link_type = 1;
        std::vector<char> raw(frame.begin(), frame.end());
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    };
    const std::string head = "MESSAGE sip:bob@biloxi.com SIP/2.0\r\ncontent-length: 5\r\nCSeq: 1 MESSAGE\r\n\r\n";
    const auto a = run(1, textOverTcp(head, 5060));
    const auto b = run(2, framesweep::ethernet(0x0800, framesweep::ipv4Packet(6, tcpSegment(40000, 5060, 1000 + uint32_t(head.size()), bytesOf("hello")))));
    // the lowercase header is honoured: the message is complete only with its 5 body bytes
    EXPECT_EQ(b.protocol, "SIP") << a.protocol << " / " << b.info;
}

TEST(Rtsp, StartLineIsValidatedAndFramed) {
    const std::string req = "DESCRIBE rtsp://example.com/media.mp4 RTSP/1.0\r\nCSeq: 2\r\ncontent-length: 3\r\n\r\nabc";
    EXPECT_EQ(frameRtsp(req.data(), req.size()).kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(frameRtsp(req.data(), req.size()).length, req.size());
    EXPECT_EQ(frameRtsp(req.data(), req.size() - 1).kind, StreamFrame::Kind::NeedMore);
    const std::string http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    EXPECT_EQ(frameRtsp(http.data(), http.size()).kind, StreamFrame::Kind::Reject);
    const std::string sip = "SIP/2.0 200 OK\r\n\r\n";
    EXPECT_EQ(frameRtsp(sip.data(), sip.size()).kind, StreamFrame::Kind::Reject) << "SIP is not RTSP";
    const std::string big = "RTSP/1.0 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n";
    EXPECT_EQ(frameRtsp(big.data(), big.size()).kind, StreamFrame::Kind::Reject);

    const auto pkt = framesweep::parseEthernet(textOverTcp(req, 554));
    EXPECT_EQ(pkt.protocol, "RTSP");
    EXPECT_EQ(pkt.info, "DESCRIBE rtsp://example.com/media.mp4 RTSP/1.0");
    EXPECT_EQ(framesweep::parseEthernet(textOverTcp(http, 554)).protocol, "TCP");
}

TEST(Rtp, HeaderLayoutFollowsRfc3550) {
    // V=2 P=0 X=0 CC=2 -> 0x82; M=0 PT=96 -> 0x60; seq 0xfffe; timestamp 0x00002710 (10000); SSRC 0xdeadbeef; CSRCs 1 and 2
    const Bytes pdu = {0x82, 0x60, 0xff, 0xfe, 0x00, 0x00, 0x27, 0x10, 0xde, 0xad, 0xbe, 0xef,
                       0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb};
    packet::PacketInfo pkt(1);
    network::TCPConnection conn;
    const char *p = reinterpret_cast<const char *>(pdu.data());
    dissect::Context ctx{pkt, p, pdu.size(), conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtp(ctx, p, pdu.size());
    EXPECT_EQ(pkt.protocol, "RTP");
    EXPECT_EQ(pkt.app_type, 96);
    EXPECT_EQ(pkt.info, "PT=96, SSeq=65534, TS=10000, SSRC=0xdeadbeef");
    ASSERT_EQ(pkt.fields.size(), 1u);
    EXPECT_EQ(pkt.fields[0].length, 20u) << "12 byte header + 2 CSRC identifiers";
    // 15 CSRCs promised, only the 12 byte header present: the layer stays inside
    const Bytes cut = {0x8f, 0x00, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2};
    packet::PacketInfo pkt2(1);
    dissect::Context ctx2{pkt2, reinterpret_cast<const char *>(cut.data()), cut.size(), conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtp(ctx2, reinterpret_cast<const char *>(cut.data()), cut.size());
    framesweep::expectInside(pkt2, cut.size(), "csrc count beyond the packet");
}

TEST(Voip, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(sipOverUdp(kCompactInvite), 41);
    framesweep::sweep(textOverTcp(kCompactInvite, 5060), 42);
    framesweep::sweep(textOverTcp("DESCRIBE rtsp://h/m RTSP/1.0\r\nCSeq: 1\r\ncontent-length: 4\r\n\r\nabcd", 554), 43);
    framesweep::sweep(sipOverUdp("SIP/2.0 200 OK\r\nContent-Length: 18446744073709551615\r\nCall-ID: z\r\n\r\n"), 44);
    directSweep(dissectRtp, {0x82, 0x60, 0xff, 0xfe, 0x00, 0x00, 0x27, 0x10, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1, 0, 0, 0, 2, 0xaa}, 45);
    directSweep(dissectRtcp, {0x81, 0xc8, 0x00, 0x06, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 0}, 46);
    directSweep(dissectSip, bytesOf(kCompactInvite), 47);
    directSweep(dissectRtsp, bytesOf("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"), 48);
}

TEST(Voip, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"SIP", "RTSP", "RTP", "RTCP"});
}

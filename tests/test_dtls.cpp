// The DTLS dissector (dissect/dtls.cpp) on hand-built datagrams: recognition by content and by port, the record header and the
// handshake fragment header, ClientHello with cookie, HelloVerifyRequest, ServerHello, Certificate, handshake messages split
// into fragments across datagrams in every order (reassembly in the load pass, "Reassembled in" on the earlier fragments), a
// retransmitted flight, damaged fragments, DTLS 1.3, and a truncation / byte flip sweep over every datagram.
//
// Oracles: the byte layouts are RFC 6347 section 4.1 / 4.2.1 (record, handshake header, ClientHello, HelloVerifyRequest) and
// RFC 5246 for the hello bodies, written out by hand in the helpers below (nothing is produced by the code under test). The
// certificate is a P-256 certificate made with `openssl req -x509 ... -subj "/CN=dtls.example.test/O=ImShark Test" -addext
// subjectAltName=DNS:dtls.example.test,DNS:alt.example.test`; `openssl x509 -noout -subject -serial -ext subjectAltName` gave
// the subject, the serial 57F4D156153812DA9DC7F58CD69763B7803003E1 and the two names the tests expect.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include <core.h>

#include "tls_support.h"

namespace {
    using tlstest::find;
    using tlstest::Loaded;

    std::string be(uint64_t v, int bytes) {
        std::string s;
        for (int i = bytes - 1; i >= 0; --i) s += static_cast<char>((v >> (8 * i)) & 0xff);
        return s;
    }

    std::string record(uint8_t type, uint16_t version, uint16_t epoch, uint64_t seq, const std::string &body) {
        return std::string(1, static_cast<char>(type)) + be(version, 2) + be(epoch, 2) + be(seq, 6) + be(body.size(), 2) + body;
    }

    // a handshake fragment: the whole message `body` is announced, `length` bytes from `offset` are carried (npos: all)
    std::string handshake(uint8_t type, uint16_t messageSeq, const std::string &body, uint32_t offset = 0, size_t length = std::string::npos) {
        if (length == std::string::npos) length = body.size() - offset;
        return std::string(1, static_cast<char>(type)) + be(body.size(), 3) + be(messageSeq, 2) + be(offset, 3) + be(length, 3) + body.substr(offset, length);
    }

    std::string randomOf(uint8_t first) {
        std::string r;
        for (int i = 0; i < 32; ++i) r += static_cast<char>(first + i);
        return r;
    }

    std::string clientHelloBody(const std::string &cookie, const std::string &sni, uint8_t randomFirst = 0) {
        std::string b = be(0xfefd, 2) + randomOf(randomFirst) + std::string(1, '\0') + std::string(1, static_cast<char>(cookie.size())) + cookie +
                        be(4, 2) + be(0xc02f, 2) + be(0xc030, 2) + std::string("\x01\x00", 2);
        std::string ext;
        if (!sni.empty()) {
            const std::string list = std::string(1, '\0') + be(sni.size(), 2) + sni;
            ext += be(0, 2) + be(2 + list.size(), 2) + be(list.size(), 2) + list;
        }
        ext += be(23, 2) + be(0, 2);   // extended_master_secret
        return b + be(ext.size(), 2) + ext;
    }

    std::string serverHelloBody(uint16_t cipher = 0xc02f, uint8_t randomFirst = 0x80) {
        return be(0xfefd, 2) + randomOf(randomFirst) + std::string(1, '\0') + be(cipher, 2) + std::string(1, '\0') + be(0, 2);
    }

    std::string helloVerifyBody(const std::string &cookie) { return be(0xfefd, 2) + std::string(1, static_cast<char>(cookie.size())) + cookie; }

    const std::string kCertificateDer = []() {
        const std::string h =
            "308201ee30820193a003020102021457f4d156153812da9dc7f58cd69763b7803003e1300a06082a8648ce3d0403023033311a301806035504030c1164746c732e6578616d706c652e7465737431153013060355040a0c0c496d536861726b2054657374301e170d3236313030363039353230345a170d3336313030333039353230345a3033311a301806035504030c1164746c732e6578616d706c652e7465737431153013060355040a0c0c496d536861726b20546573743059301306072a8648ce3d020106082a8648ce3d03010703420004bca27af4df52ffed74a0e0c18ac9f644ab43b2202f55bf5fa3f5e75f1264a6cea9c6ad7b3f585429953f9199dca36ced654df6140e3d617f5a85c93373a5ea63a38184308181301d0603551d0e04160414d6d8f8f9804b38a1bc20873025cc11fa5739c6d5301f0603551d23041830168014d6d8f8f9804b38a1bc20873025cc11fa5739c6d5300f0603551d130101ff040530030101ff302e0603551d1104273025821164746c732e6578616d706c652e746573748210616c742e6578616d706c652e74657374300a06082a8648ce3d040302034900304602210080b447c04bd7ef0b77027b598373d0ea96b81261bfe50e2d3d99955a3d3dd7b1022100d960d75ba139583ce1683edb37e1cd4666e9e2a8a2518a0359b3c52d042bf135";
        const auto v = support::hex(h);
        return std::string(v.begin(), v.end());
    }();

    std::string certificateBody() { return be(kCertificateDer.size() + 3, 3) + be(kCertificateDer.size(), 3) + kCertificateDer; }

    std::string port(uint16_t p) {
        char text[8];
        std::snprintf(text, sizeof text, "%04x", p);
        return text;
    }

    constexpr uint16_t kClientPort = 50000, kServerPort = 4433;

    // client -> server
    std::vector<char> toServer(const std::string &payload, uint16_t dport = kServerPort) { return support::udpPacket("0a000001", "0a000002", port(kClientPort), port(dport), payload); }
    // server -> client
    std::vector<char> toClient(const std::string &payload, uint16_t sport = kServerPort) { return support::udpPacket("0a000002", "0a000001", port(sport), port(kClientPort), payload); }

    std::string hsRecord(uint64_t seq, const std::string &handshakes, uint16_t version = 0xfefd) { return record(22, version, 0, seq, handshakes); }

    struct Cap {
        std::vector<std::vector<char>> frames;
        std::unique_ptr<Loaded> loaded;
        const Loaded &load(const std::string &name) {
            loaded = std::make_unique<Loaded>(support::pcapBytes(frames), "dtls_" + name + ".pcap", false);
            EXPECT_TRUE(loaded->ok) << loaded->message;
            return *loaded;
        }
    };

    std::string textOf(const std::vector<packet::Field> &fields) {
        std::string out;
        for (const auto &f: fields) out += f.text + "\n" + textOf(f.children);
        return out;
    }
} // namespace

TEST(DtlsRecognition, AValidRecordIsDtlsOnAnyPort) {
    Cap c;
    c.frames = {toServer(hsRecord(0, handshake(1, 0, clientHelloBody("", "example.test"))), 12345)};
    const Loaded &cap = c.load("anyport");
    ASSERT_EQ(cap.packets.size(), 1u);
    EXPECT_EQ(cap.packets[0].protocol, "DTLS");
    EXPECT_EQ(cap.packets[0].info, "Client Hello (SNI=example.test)");
    EXPECT_EQ(cap.packets[0].app_text, "example.test");
    EXPECT_EQ(cap.packets[0].app_type, 1);
    EXPECT_EQ(cap.packets[0].app_flags, 0xfefd);
}

TEST(DtlsRecognition, BytesThatAreNotRecordsStayWhatTheyWere) {
    const std::string valid = hsRecord(0, handshake(1, 0, clientHelloBody("", "")));
    std::string badVersion = valid;
    badVersion[1] = 0x03; badVersion[2] = 0x03;                          // a TLS version
    std::string badType = valid;
    badType[0] = 0x1a;                                                   // 26
    std::string tooLong = valid;
    tooLong[11] = 0x7f;                                                  // the length runs past the datagram
    std::string trailing = valid + "garbage";                            // not every byte belongs to a record
    Cap c;
    for (const std::string &payload: {badVersion, badType, tooLong, trailing}) c.frames.push_back(toServer(payload, 12345));
    // on the DTLS ports the same bytes are raw UDP as well (a bad header), except the cut one, whose header is fine
    for (const std::string &payload: {badVersion, badType}) c.frames.push_back(toServer(payload, 4433));
    c.frames.push_back(toServer("hello", 5684));
    const Loaded &cap = c.load("notdtls");
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        EXPECT_EQ(cap.packets[i].protocol, "UDP") << i;
        EXPECT_NE(cap.packets[i].info.find("Len="), std::string::npos) << i;
    }
}

TEST(DtlsRecognition, TheDtlsPortsAcceptACutRecordAndGeneralPortsDoNot) {
    const std::string valid = hsRecord(0, handshake(1, 0, clientHelloBody("", "")));
    const std::string cut = valid.substr(0, valid.size() - 20);
    Cap c;
    c.frames = {toServer(cut, 4433), toServer(cut, 5684), toServer(cut, 12345)};
    const Loaded &cap = c.load("cut");
    EXPECT_EQ(cap.packets[0].protocol, "DTLS");
    EXPECT_EQ(cap.packets[1].protocol, "DTLS");
    EXPECT_EQ(cap.packets[2].protocol, "UDP");
    EXPECT_NE(cap.packets[0].info.find("[fragment]"), std::string::npos) << cap.packets[0].info;
}

TEST(DtlsRecognition, StunAndTurnPortsAreDtlsOnlyWhenTheContentMatches) {
    const std::string stun = std::string("\x00\x01\x00\x00\x21\x12\xa4\x42", 8) + std::string(12, 'x');   // a Binding request (RFC 5389)
    Cap c;
    c.frames = {toServer(stun, 3478), toServer(stun, 5349), toServer(hsRecord(0, handshake(1, 0, clientHelloBody("", ""))), 3478),
                toServer(hsRecord(0, handshake(1, 0, clientHelloBody("", ""))), 5349)};
    const Loaded &cap = c.load("stun");
    EXPECT_EQ(cap.packets[0].protocol, "UDP");
    EXPECT_EQ(cap.packets[1].protocol, "UDP");
    EXPECT_EQ(cap.packets[2].protocol, "DTLS");
    EXPECT_EQ(cap.packets[3].protocol, "DTLS");
}

TEST(DtlsRecognition, Dtls13UnifiedHeaderIsFlaggedOnTheDtlsPortsOnly) {
    // 001 C=0 S=1 L=1 EE=10: 16 bit sequence number, length present, epoch bits 2
    const std::string unified = std::string(1, static_cast<char>(0x2e)) + be(0x1234, 2) + be(6, 2) + "abcdef";
    Cap c;
    c.frames = {toServer(unified, 4433), toServer(unified, 5684), toServer(unified, 12345), toServer(std::string(1, static_cast<char>(0x3f)) + "xyz", 4433)};
    const Loaded &cap = c.load("dtls13");
    EXPECT_EQ(cap.packets[0].protocol, "DTLS");
    EXPECT_EQ(cap.packets[0].info, "DTLS 1.3 record (unified header, not decoded)");
    EXPECT_EQ(cap.packets[0].app_flags, 0xfefc);
    EXPECT_EQ(cap.packets[1].protocol, "DTLS");
    EXPECT_EQ(cap.packets[2].protocol, "UDP") << "too ambiguous to claim on an arbitrary port";
    const auto d = const_cast<Loaded &>(cap).details(0);
    EXPECT_NE(textOf(d.fields).find("DTLS 1.3 Record Layer"), std::string::npos);
    EXPECT_NE(textOf(d.fields).find("not decoded"), std::string::npos);
}

TEST(DtlsRecognition, DecodeAsNamesDtlsForAPort) {
    dissect::Registry registry = dissect::Registry::builtin();
    std::string error;
    ASSERT_TRUE(registry.decodeAs(false, 9999, "DTLS", &error)) << error;
    const auto frame = toServer(std::string(1, static_cast<char>(0x2e)) + be(1, 2) + be(2, 2) + "ab", 9999);
    packet::PacketParser parser(registry);
    packet::PacketInfo info(1);
    info.link_type = 1;
    std::vector<char> bytes = frame;
    parser.parsePacket(info, bytes);
    EXPECT_EQ(info.protocol, "DTLS");
    // the name is listed for UDP and not for TCP
    const auto udp = dissect::Registry::builtin().protocolNames(false), tcp = dissect::Registry::builtin().protocolNames(true);
    EXPECT_NE(std::find(udp.begin(), udp.end(), "DTLS"), udp.end());
    EXPECT_EQ(std::find(tcp.begin(), tcp.end(), "DTLS"), tcp.end());
}

TEST(DtlsRecordHeader, RecordHeaderFieldsAreDecodedWithTheirOffsets) {
    const uint64_t seq = 0x0102030405ull;
    Cap c;
    c.frames = {toServer(record(22, 0xfeff, 0, seq, handshake(1, 0, clientHelloBody("", ""))))};
    const Loaded &cap = c.load("header");
    auto d = const_cast<Loaded &>(cap).details(0);
    const packet::Field *dtls = find(d.fields, "Datagram Transport Layer Security");
    ASSERT_NE(dtls, nullptr);
    EXPECT_EQ(dtls->offset, 14u + 20 + 8);
    const packet::Field *r = find(dtls->children, "DTLS 1.0 Record Layer: Handshake");
    ASSERT_NE(r, nullptr);
    ASSERT_GE(r->children.size(), 5u);
    EXPECT_EQ(r->children[0].text, "Content Type: Handshake (22)");
    EXPECT_EQ(r->children[0].offset, dtls->offset);
    EXPECT_EQ(r->children[1].text, "Version: DTLS 1.0 (0xfeff)");
    EXPECT_EQ(r->children[2].text, "Epoch: 0");
    EXPECT_EQ(r->children[3].text, "Sequence Number: " + std::to_string(seq));
    EXPECT_EQ(r->children[3].length, 6u);
    EXPECT_EQ(r->children[4].text.rfind("Length: ", 0), 0u);
    tlstest::expectInside(d.fields, d.raw_data.size());
    // the compact facts the filter fields read
    EXPECT_EQ(cap.packets[0].app_code & 0x1f, 22);
    EXPECT_EQ(cap.packets[0].app_flags, 0xfeff);
    EXPECT_EQ(cap.packets[0].tcp_pdu_start, static_cast<uint32_t>(seq));
    EXPECT_EQ(cap.packets[0].tcp_pdu_len, static_cast<uint32_t>(seq >> 32));
}

TEST(DtlsRecordHeader, Epoch48BitSequenceAndTheSummaryFields) {
    const uint64_t seq = 0xabcdef012345ull;
    Cap c;
    c.frames = {toServer(record(23, 0xfefd, 7, seq, std::string(40, 'x')))};
    const Loaded &cap = c.load("epochseq");
    const auto &p = cap.packets[0];
    EXPECT_EQ(p.protocol, "DTLS");
    EXPECT_EQ(p.tcp_pdu_len >> 16, 7u);
    EXPECT_EQ(p.tcp_pdu_len & 0xffff, static_cast<uint32_t>(seq >> 32));
    EXPECT_EQ(p.tcp_pdu_start, static_cast<uint32_t>(seq));
    EXPECT_EQ((static_cast<uint64_t>(p.tcp_pdu_len & 0xffff) << 32) | p.tcp_pdu_start, seq);
}

TEST(DtlsHandshake, ClientHelloWithCookieShowsTheFragmentHeaderAndTheHelloFields) {
    const std::string cookie = "COOKIE1234567890";
    Cap c;
    c.frames = {toServer(hsRecord(1, handshake(1, 1, clientHelloBody(cookie, "example.test"))))};
    const Loaded &cap = c.load("clienthello");
    auto d = const_cast<Loaded &>(cap).details(0);
    EXPECT_EQ(cap.packets[0].info, "Client Hello (SNI=example.test)");
    EXPECT_EQ(cap.packets[0].app_code >> 5, 16 + 1) << "cookie length + 1 (0 means no cookie)";
    EXPECT_EQ(cap.packets[0].app_type, 1);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Handshake Type: Client Hello (1)"), std::string::npos) << t;
    EXPECT_NE(t.find("Message Sequence: 1"), std::string::npos);
    EXPECT_NE(t.find("Fragment Offset: 0"), std::string::npos);
    EXPECT_NE(t.find("Fragment Length: "), std::string::npos);
    EXPECT_NE(t.find("Cookie Length: 16"), std::string::npos);
    EXPECT_NE(t.find("Cookie"), std::string::npos);
    EXPECT_NE(t.find("Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)"), std::string::npos);
    EXPECT_NE(t.find("Server Name: example.test"), std::string::npos);
    const packet::Field *cookieNode = find(d.fields, "Cookie");
    ASSERT_NE(cookieNode, nullptr);
    // the cookie node points at the cookie bytes in the frame
    const std::string frame(d.raw_data.begin(), d.raw_data.end());
    const packet::Field *cookieBytes = nullptr;
    for (const packet::Field *f = find(d.fields, "Cookie Length"); f; f = nullptr) cookieBytes = f;
    ASSERT_NE(cookieBytes, nullptr);
    EXPECT_EQ(frame.substr(cookieBytes->offset + 1, cookie.size()), cookie);
    tlstest::expectInside(d.fields, d.raw_data.size());
}

TEST(DtlsHandshake, HelloVerifyRequestCarriesTheCookie) {
    Cap c;
    c.frames = {toServer(hsRecord(0, handshake(1, 0, clientHelloBody("", "example.test")))),
                toClient(hsRecord(0, handshake(3, 0, helloVerifyBody("0123456789abcdefghij")))),
                toServer(hsRecord(1, handshake(1, 1, clientHelloBody("0123456789abcdefghij", "example.test"))))};
    const Loaded &cap = c.load("hvr");
    EXPECT_EQ(cap.packets[0].app_code >> 5, 1) << "a ClientHello without a cookie: length 0, stored as 1";
    EXPECT_EQ(cap.packets[1].info, "Hello Verify Request");
    EXPECT_EQ(cap.packets[1].app_type, 3);
    EXPECT_EQ(cap.packets[1].app_code >> 5, 21);
    EXPECT_EQ(cap.packets[2].app_code >> 5, 21);
    auto d = const_cast<Loaded &>(cap).details(1);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Handshake Type: Hello Verify Request (3)"), std::string::npos) << t;
    EXPECT_NE(t.find("Version: DTLS 1.2 (0xfefd)"), std::string::npos);
    EXPECT_NE(t.find("Cookie Length: 20"), std::string::npos);
    tlstest::expectInside(d.fields, d.raw_data.size());
    // the retransmitted ClientHello of the second round trip is the same connection
    EXPECT_EQ(cap.fp.sessions().dtlsTable().sessionCount(), 1u);
}

TEST(DtlsHandshake, SeveralRecordsInOneDatagram) {
    const std::string datagram = hsRecord(2, handshake(2, 1, serverHelloBody())) + hsRecord(3, handshake(11, 2, certificateBody())) +
                                 hsRecord(4, handshake(14, 3, "")) + record(20, 0xfefd, 0, 5, "\x01") ;
    Cap c;
    c.frames = {toClient(datagram)};
    const Loaded &cap = c.load("flight");
    EXPECT_EQ(cap.packets[0].protocol, "DTLS");
    EXPECT_EQ(cap.packets[0].info, "Server Hello (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), Certificate, Server Hello Done, Change Cipher Spec");
    EXPECT_EQ(cap.packets[0].app_text2, "dtls.example.test");
    auto d = const_cast<Loaded &>(cap).details(0);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Subject Alternative Names: dtls.example.test, alt.example.test"), std::string::npos) << t;
    EXPECT_NE(t.find("Serial Number: 0x57f4d156153812da9dc7f58cd69763b7803003e1"), std::string::npos) << t;
    std::vector<std::string> records;
    tlstest::collect(d.fields, "DTLS 1.2 Record Layer", records);
    EXPECT_EQ(records.size(), 4u);
    tlstest::expectInside(d.fields, d.raw_data.size());
}

TEST(DtlsHandshake, TheAlertOfAClearRecordIsDecoded) {
    Cap c;
    c.frames = {toClient(record(21, 0xfefd, 0, 9, std::string("\x02\x28", 2)))};
    const Loaded &cap = c.load("alert");
    EXPECT_EQ(cap.packets[0].info, "Alert");
    auto d = const_cast<Loaded &>(cap).details(0);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Level: Fatal (2)"), std::string::npos) << t;
    EXPECT_NE(t.find("Description: handshake_failure (40)"), std::string::npos);
}

TEST(DtlsHandshake, ACutHandshakeFragmentAndOneOutsideItsMessageAreReportedNotTrusted) {
    Cap c;
    const std::string whole = handshake(1, 0, clientHelloBody("", "example.test"));
    // a fragment whose offset + length lies beyond the message length
    std::string bad = whole.substr(0, 6) + be(10, 3) + be(1000, 3) + whole.substr(12);
    c.frames = {toServer(hsRecord(0, bad)), toServer(hsRecord(1, whole.substr(0, 30)) )};
    const Loaded &cap = c.load("badfrag");
    EXPECT_NE(cap.packets[0].info.find("malformed fragment"), std::string::npos) << cap.packets[0].info;
    auto d = const_cast<Loaded &>(cap).details(0);
    EXPECT_NE(textOf(d.fields).find("Expert Info (Warning/Malformed)"), std::string::npos);
    EXPECT_NE(cap.packets[1].info.find("fragment"), std::string::npos);
}

// ---- reassembly ----------------------------------------------------------------------------------------------------------------

namespace {
    // the datagrams of one message split into `parts` fragments, one record each; message_seq 1, record sequence numbers 10...
    std::vector<std::string> fragmentDatagrams(uint8_t type, const std::string &body, const std::vector<std::pair<uint32_t, uint32_t>> &parts) {
        std::vector<std::string> out;
        uint64_t seq = 10;
        for (const auto &p: parts) out.push_back(hsRecord(seq++, handshake(type, 1, body, p.first, p.second)));
        return out;
    }
} // namespace

TEST(DtlsReassembly, AFragmentedClientHelloIsPutTogetherInEveryArrivalOrder) {
    const std::string body = clientHelloBody("0123456789abcdef", "fragmented.example.test");
    const uint32_t n = static_cast<uint32_t>(body.size());
    const std::vector<std::pair<uint32_t, uint32_t>> parts = {{0, 40}, {40, 40}, {80, n - 80}};
    const auto datagrams = fragmentDatagrams(1, body, parts);
    std::vector<int> order = {0, 1, 2};
    int checked = 0;
    do {
        Cap c;
        for (int i: order) c.frames.push_back(toServer(datagrams[i]));
        const Loaded &cap = c.load("reasm" + std::to_string(checked));
        const size_t last = order.size() - 1;
        // the completing packet shows the whole message
        const auto &done = cap.packets[last];
        EXPECT_EQ(done.info.rfind("Client Hello (SNI=fragmented.example.test) [Reassembled from 3 packet(s)]", 0), 0u) << done.info;
        EXPECT_EQ(done.app_text, "fragmented.example.test");
        EXPECT_EQ(done.app_code >> 5, 17);
        // the earlier ones say where
        for (size_t i = 0; i < last; ++i) {
            const auto &p = cap.packets[i];
            EXPECT_NE(p.info.find("Client Hello [fragment "), std::string::npos) << p.info;
            EXPECT_NE(p.info.find("[Reassembled in #3]"), std::string::npos) << p.info;
        }
        // detail building agrees with the load pass for every packet
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            auto d = const_cast<Loaded &>(cap).details(i);
            EXPECT_EQ(d.info, cap.packets[i].info) << i;
            EXPECT_EQ(d.protocol, cap.packets[i].protocol);
            EXPECT_EQ(d.app_text, cap.packets[i].app_text);
            EXPECT_EQ(d.app_code, cap.packets[i].app_code);
            EXPECT_EQ(d.app_type, cap.packets[i].app_type);
            tlstest::expectInside(d.fields, d.raw_data.size());
        }
        auto d = const_cast<Loaded &>(cap).details(last);
        const std::string t = textOf(d.fields);
        EXPECT_NE(t.find("Reassembled DTLS handshake message (" + std::to_string(n) + " bytes) from frame(s) #"), std::string::npos) << t;
        EXPECT_NE(t.find("Server Name: fragmented.example.test"), std::string::npos);
        EXPECT_NE(t.find("Cookie Length: 16"), std::string::npos);
        auto first = const_cast<Loaded &>(cap).details(0);
        EXPECT_NE(textOf(first.fields).find("[Reassembled in #3]"), std::string::npos);
        ++checked;
    } while (std::next_permutation(order.begin(), order.end()));
    EXPECT_EQ(checked, 6);
}

TEST(DtlsReassembly, AFragmentedCertificateGivesTheSubjectOnTheCompletingPacket) {
    const std::string body = certificateBody();
    const uint32_t n = static_cast<uint32_t>(body.size());
    const auto datagrams = fragmentDatagrams(11, body, {{0, 200}, {200, 200}, {400, n - 400}});
    Cap c;
    c.frames = {toClient(datagrams[0]), toClient(datagrams[1]), toClient(datagrams[2])};
    const Loaded &cap = c.load("certfrag");
    EXPECT_EQ(cap.packets[0].app_text2, "") << "half a certificate has no subject yet";
    EXPECT_EQ(cap.packets[2].app_text2, "dtls.example.test");
    EXPECT_NE(cap.packets[2].info.find("Certificate [Reassembled from 3 packet(s)]"), std::string::npos) << cap.packets[2].info;
    auto d = const_cast<Loaded &>(cap).details(2);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Subject: "), std::string::npos) << t;
    EXPECT_NE(t.find("Subject Alternative Names: dtls.example.test, alt.example.test"), std::string::npos);
}

TEST(DtlsReassembly, SeveralFragmentsOfDifferentMessagesInOneDatagram) {
    // datagram 1: ServerHello whole + the first half of the Certificate; datagram 2: the rest of the Certificate + ServerHelloDone
    const std::string cert = certificateBody();
    const uint32_t half = static_cast<uint32_t>(cert.size() / 2);
    Cap c;
    c.frames = {toClient(hsRecord(1, handshake(2, 1, serverHelloBody()) + handshake(11, 2, cert, 0, half))),
                toClient(hsRecord(2, handshake(11, 2, cert, half) + handshake(14, 3, "")))};
    const Loaded &cap = c.load("mixed");
    EXPECT_NE(cap.packets[0].info.find("Server Hello"), std::string::npos);
    EXPECT_NE(cap.packets[0].info.find("Certificate [fragment 0-"), std::string::npos) << cap.packets[0].info;
    EXPECT_NE(cap.packets[0].info.find("[Reassembled in #2]"), std::string::npos);
    EXPECT_NE(cap.packets[1].info.find("Certificate [Reassembled from 2 packet(s)], Server Hello Done"), std::string::npos) << cap.packets[1].info;
    for (size_t i = 0; i < 2; ++i) {
        auto d = const_cast<Loaded &>(cap).details(i);
        EXPECT_EQ(d.info, cap.packets[i].info);
        tlstest::expectInside(d.fields, d.raw_data.size());
    }
}

TEST(DtlsReassembly, ARetransmittedFlightIsMarkedAndAFirstFragmentOfItStaysPending) {
    const std::string hello = handshake(1, 0, clientHelloBody("", "example.test"));
    Cap c;
    c.frames = {toServer(hsRecord(0, hello)), toServer(hsRecord(1, hello))};
    const Loaded &cap = c.load("retransmit");
    EXPECT_EQ(cap.packets[0].info, "Client Hello (SNI=example.test)");
    EXPECT_EQ(cap.packets[1].info, "Client Hello (SNI=example.test) [Retransmission]");
    auto d = const_cast<Loaded &>(cap).details(1);
    EXPECT_EQ(d.info, cap.packets[1].info);
    EXPECT_NE(textOf(d.fields).find("[Retransmission of the message completed in #1]"), std::string::npos);
    EXPECT_EQ(cap.fp.sessions().dtlsTable().sessionCount(), 1u);

    // a fragmented message sent twice: the second set completes again and is marked
    const std::string body = clientHelloBody("", "example.test");
    const auto first = fragmentDatagrams(1, body, {{0, 50}, {50, static_cast<uint32_t>(body.size() - 50)}});
    Cap r;
    r.frames = {toServer(first[0]), toServer(first[1]), toServer(first[0]), toServer(first[1])};
    const Loaded &twice = r.load("retransmit2");
    EXPECT_EQ(twice.packets[1].info.find("[Retransmission]"), std::string::npos);
    EXPECT_NE(twice.packets[3].info.find("[Retransmission]"), std::string::npos) << twice.packets[3].info;
    EXPECT_NE(twice.packets[2].info.find("[Reassembled in #4]"), std::string::npos) << twice.packets[2].info;
}

TEST(DtlsReassembly, DisagreeingOverlapAndAnotherLengthAreFlaggedInTheTree) {
    const std::string body(60, 'A');
    std::string other(60, 'A');
    other.replace(30, 10, std::string(10, 'Z'));
    Cap c;
    c.frames = {toServer(hsRecord(1, handshake(1, 1, body, 0, 40))),
                toServer(hsRecord(2, handshake(1, 1, other, 30, 30)))};     // bytes 30..39 overlap with different data
    const Loaded &cap = c.load("overlap");
    auto d = const_cast<Loaded &>(cap).details(1);
    EXPECT_NE(textOf(d.fields).find("carried different bytes than an earlier copy"), std::string::npos) << textOf(d.fields);

    Cap m;
    m.frames = {toServer(hsRecord(1, handshake(1, 1, body, 0, 30))), toServer(hsRecord(2, handshake(1, 1, std::string(90, 'A'), 30, 30)))};
    const Loaded &mismatch = m.load("mismatch");
    EXPECT_NE(mismatch.packets[1].info.find("[message length differs from the first fragment]"), std::string::npos) << mismatch.packets[1].info;
    auto md = const_cast<Loaded &>(mismatch).details(1);
    EXPECT_NE(textOf(md.fields).find("another message length than the first fragment"), std::string::npos);
}

TEST(DtlsReassembly, ATableThatRanOutOfRoomSaysSoInsteadOfPretending) {
    const std::string body = clientHelloBody("", "example.test");
    const auto datagrams = fragmentDatagrams(1, body, {{0, 50}, {50, static_cast<uint32_t>(body.size() - 50)}});
    Cap c;
    c.frames = {toServer(datagrams[0]), toServer(datagrams[1])};
    const std::string path = support::writeTemp("dtls_lost.pcap", support::pcapBytes(c.frames));
    core::FileProcessor fp;
    fp.sessions().setMaxMemoryPerTable(100);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));
    EXPECT_TRUE(fp.sessions().isTableStateLost("dtls"));
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[0], d, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
    EXPECT_NE(d.info.find("the DTLS session table lost state"), std::string::npos) << d.info;
    EXPECT_NE(textOf(d.fields).find("lost state"), std::string::npos);
    std::remove(path.c_str());
}

// ---- damaged input -------------------------------------------------------------------------------------------------------------

TEST(DtlsSweeps, EveryCutAndEveryFlippedByteOfEveryDatagramStaysInsideTheFrame) {
    const std::string body = clientHelloBody("0123456789abcdef", "example.test");
    std::vector<std::string> payloads = {
        hsRecord(0, handshake(1, 0, clientHelloBody("", "example.test"))),
        hsRecord(1, handshake(3, 0, helloVerifyBody("0123456789abcdef"))),
        hsRecord(2, handshake(2, 1, serverHelloBody())) + hsRecord(3, handshake(11, 2, certificateBody(), 0, 120)) + record(20, 0xfefd, 0, 4, "\x01"),
        hsRecord(5, handshake(1, 1, body, 40, body.size() - 40)),
        record(21, 0xfefd, 0, 6, std::string("\x01\x00", 2)),
        record(23, 0xfefd, 1, 7, std::string(60, 'e')),
        std::string(1, static_cast<char>(0x2c)) + be(0x0102, 2) + be(8, 2) + "12345678",
    };
    for (size_t k = 0; k < payloads.size(); ++k) {
        SCOPED_TRACE("payload " + std::to_string(k));
        const std::string &payload = payloads[k];
        std::vector<std::vector<char>> frames;
        for (size_t n = 0; n <= payload.size(); ++n) frames.push_back(toServer(payload.substr(0, n), 4433));
        for (size_t i = 0; i < payload.size(); ++i) {
            std::string flipped = payload;
            flipped[i] = static_cast<char>(flipped[i] ^ 0x5a);
            frames.push_back(toServer(flipped, 4433));
        }
        Loaded cap(support::pcapBytes(frames), "dtls_sweep" + std::to_string(k) + ".pcap", false);
        ASSERT_TRUE(cap.ok) << cap.message;
        ASSERT_EQ(cap.packets.size(), frames.size());
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            auto d = cap.details(i);
            tlstest::expectInside(d.fields, d.raw_data.size());
            EXPECT_EQ(d.info, cap.packets[i].info) << i;
            EXPECT_EQ(d.protocol, cap.packets[i].protocol) << i;
        }
    }
}

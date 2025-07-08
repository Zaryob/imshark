#include <gtest/gtest.h>

#include <functional>
#include <random>

#include <filter/filter.h>

#include "support.h"

using support::hex;

namespace {
    std::string raw(const std::string &hexText) { auto v = hex(hexText); return std::string(v.begin(), v.end()); }

    packet::PacketInfo tcpPayload(const std::string &payload, const char *sport = "c350", const char *dport = "0050") {
        return support::parse(support::tcpPacket("0a000001", "0a000002", sport, dport, "00000001", "00000001", "18", payload));
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        return r.ok && r.filter.matches(p);
    }

    // ---- TLS record builders
    std::string u8(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%02x", v); return b; }
    std::string u16(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return b; }
    std::string u24(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%06x", v); return b; }
    std::string lenPrefixed16(const std::string &hexBody) { return u16(static_cast<unsigned>(hexBody.size() / 2)) + hexBody; }

    std::string record(unsigned type, unsigned version, const std::string &body) { return u8(type) + u16(version) + u16(static_cast<unsigned>(body.size() / 2)) + body; }
    std::string handshake(unsigned type, const std::string &body) { return u8(type) + u24(static_cast<unsigned>(body.size() / 2)) + body; }
    const std::string kRandom(64, '1');

    std::string clientHello(const std::string &sni, bool tls13 = true) {
        std::string ext;
        if (!sni.empty()) {
            const std::string name = support::hexOf(sni);
            const std::string list = "00" + u16(static_cast<unsigned>(name.size() / 2)) + name;
            ext += u16(0) + lenPrefixed16(lenPrefixed16(list.substr(0)).substr(0));
            // server_name extension data = list length(2) + [type(1) + name length(2) + name]
            ext = u16(0) + u16(static_cast<unsigned>(2 + list.size() / 2)) + u16(static_cast<unsigned>(list.size() / 2)) + list;
        }
        if (tls13) ext += u16(43) + u16(5) + "04" + "0304" + "0303";
        ext += u16(16) + u16(14) + u16(12) + "02" + support::hexOf("h2") + "08" + support::hexOf("http/1.1");
        const std::string body = "0303" + kRandom + "00" + lenPrefixed16("1301c02f") + "0100" + lenPrefixed16(ext);
        return record(22, 0x0301, handshake(1, body));
    }

    std::string serverHello() { return record(22, 0x0303, handshake(2, "0303" + kRandom + "00" + "c02f" + "00" + u16(0))); }
} // namespace

TEST(Http, RequestIsRecognisedOnAnyPortAndFillsFilterFacts) {
    const auto p = tcpPayload("GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n", "c350", "1f90");
    EXPECT_EQ(p.protocol, "HTTP");
    EXPECT_EQ(p.info, "GET /index.html?q=1 HTTP/1.1");
    EXPECT_EQ(p.app_text, "example.com");
    EXPECT_EQ(p.app_text2, "/index.html?q=1");
    EXPECT_TRUE(matches("http.request && http.request.method == \"GET\"", p));
    EXPECT_TRUE(matches("http.host == \"example.com\" && http.request.uri contains \"index\"", p));
    EXPECT_FALSE(matches("http.response", p));
    EXPECT_FALSE(matches("http.response.code == 200", p));
    EXPECT_TRUE(matches("http && tcp.port == 8080", p));

    EXPECT_NE(find(p.fields, "Hypertext Transfer Protocol"), nullptr);
    const auto *line = find(p.fields, "GET /index.html?q=1 HTTP/1.1");
    ASSERT_NE(line, nullptr);
    EXPECT_NE(find(line->children, "Request Method: GET"), nullptr);
    EXPECT_NE(find(line->children, "Request URI: /index.html?q=1"), nullptr);
    EXPECT_NE(find(line->children, "Request Version: HTTP/1.1"), nullptr);
    EXPECT_NE(find(p.fields, "Host: example.com"), nullptr);
    EXPECT_NE(find(p.fields, "User-Agent: test"), nullptr);
    EXPECT_EQ(find(p.fields, "File Data"), nullptr);
}

TEST(Http, ResponseWithBodyAndEveryMethod) {
    const std::string body = "<html>hi</html>";
    const auto p = tcpPayload("HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 15\r\n\r\n" + body, "0050", "c350");
    EXPECT_EQ(p.protocol, "HTTP");
    EXPECT_EQ(p.info, "HTTP/1.1 404 Not Found (text/html)");
    EXPECT_EQ(p.app_code, 404);
    EXPECT_TRUE(matches("http.response && http.response.code == 404 && http.content_type contains \"text/html\"", p));
    EXPECT_TRUE(matches("http.response.code >= 400 && !http.request", p));
    EXPECT_NE(find(p.fields, "Status Code: 404"), nullptr);
    EXPECT_NE(find(p.fields, "Response Phrase: Not Found"), nullptr);
    const auto *data = find(p.fields, "File Data: 15 bytes");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->length, 15u);

    for (const char *m: {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}) {
        const auto r = tcpPayload(std::string(m) + " /x HTTP/1.0\r\n\r\n");
        EXPECT_EQ(r.protocol, "HTTP") << m;
        EXPECT_TRUE(matches(std::string("http.request.method == \"") + m + "\"", r)) << m;
    }
}

TEST(Http, NotHttpIsLeftAlone) {
    for (const char *text: {"GETX /x HTTP/1.1\r\n\r\n", "GET /x HTTP/1.1", "get / HTTP/1.1\r\n\r\n", "HTTP/2 200\r\n", "hello world\r\n", "POST\r\n"}) {
        EXPECT_EQ(tcpPayload(text).protocol, "TCP") << text;
    }
    EXPECT_EQ(tcpPayload(raw("474554200000000a")).protocol, "TCP") << "binary garbage after 'GET '";
    EXPECT_EQ(tcpPayload("GET /ok HTTP/1.1\nHost: lf-only\n\n").protocol, "HTTP") << "bare LF line ends are accepted";
}

TEST(Http, HeadersThatContinueInTheNextSegment) {
    const auto p = tcpPayload("POST /upload HTTP/1.1\r\nHost: a.example\r\nContent-Le");
    EXPECT_EQ(p.protocol, "HTTP");
    EXPECT_EQ(p.app_text, "a.example");
    EXPECT_NE(find(p.fields, "[Headers continue in later segments]"), nullptr);
}

TEST(Tls, ClientHelloWithSniAndAlpn) {
    const auto p = tcpPayload(raw(clientHello("www.example.org")), "c350", "01bb");
    EXPECT_EQ(p.protocol, "TLS");
    EXPECT_EQ(p.info, "Client Hello (SNI=www.example.org)");
    EXPECT_EQ(p.app_text, "www.example.org");
    EXPECT_EQ(p.app_type, 1);
    EXPECT_EQ(p.app_code, 22);
    EXPECT_TRUE(matches("tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"www.example.org\"", p));
    EXPECT_TRUE(matches("tls && tls.record.content_type == 22", p));
    EXPECT_NE(find(p.fields, "TLS 1.0 Record Layer: Handshake"), nullptr);
    EXPECT_NE(find(p.fields, "Handshake Protocol: Client Hello"), nullptr);
    EXPECT_NE(find(p.fields, "Extension: server_name: www.example.org"), nullptr);
    EXPECT_NE(find(p.fields, "Extension: supported_versions"), nullptr);
    EXPECT_NE(find(p.fields, "Extension: application_layer_protocol_negotiation: h2, http/1.1"), nullptr);
    EXPECT_NE(find(p.fields, "Cipher Suites (2 suites)"), nullptr);
}

TEST(Tls, ServerHelloChangeCipherSpecAndApplicationData) {
    // several records in one segment
    const auto hello = tcpPayload(raw(serverHello() + record(20, 0x0303, "01")), "01bb", "c350");
    EXPECT_EQ(hello.protocol, "TLS");
    EXPECT_EQ(hello.info, "Server Hello (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), Change Cipher Spec");
    EXPECT_EQ(hello.app_type, 2);
    EXPECT_NE(find(hello.fields, "Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)"), nullptr);

    const auto data = tcpPayload(raw(record(23, 0x0303, std::string(200, 'a'))));
    EXPECT_EQ(data.info, "Application Data");
    EXPECT_EQ(data.app_type, 0);
    EXPECT_TRUE(matches("tls.record.content_type == 23 && !tls.handshake.type", data));
    EXPECT_NE(find(data.fields, "Encrypted Application Data (100 bytes)"), nullptr);

    const auto alert = tcpPayload(raw(record(21, 0x0303, "0128")));
    EXPECT_EQ(alert.info, "Alert");
    EXPECT_NE(find(alert.fields, "Alert Message: level 1, description 40"), nullptr);
}

TEST(Tls, RecordsCutByTheSegmentEnd) {
    const auto full = record(22, 0x0303, handshake(11, std::string(1200, 'b')));   // a big Certificate
    const auto cut = tcpPayload(raw(full.substr(0, 2 * 300)));                           // only 300 bytes in this segment
    EXPECT_EQ(cut.protocol, "TLS");
    EXPECT_EQ(cut.info, "Certificate [fragment]");
}

TEST(Tls, ARecordHeaderWithoutItsBodyIsStillTls) {
    EXPECT_EQ(tcpPayload(raw("1603030100")).protocol, "TLS") << "the body is in the next segment";
}

TEST(Tls, NonTlsPayloadsAreNotClaimed) {
    for (const char *h: {"1603050000", "1603030000", "16030300", "160400000a", "1703030000", "ffffffffffff"}) {
        EXPECT_EQ(tcpPayload(raw(h)).protocol, "TCP") << h << " must not look like TLS (bad version, zero length or too short)";
    }
    EXPECT_EQ(tcpPayload("SSH-2.0-OpenSSH_9.6\r\n").protocol, "TCP");
}

TEST(HttpTls, SurviveRandomCorruption) {
    std::mt19937 rng(8);
    const std::vector<std::string> seeds = {
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nbody",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
        raw(clientHello("example.com")), raw(serverHello() + record(23, 0x0303, std::string(60, 'c'))),
    };
    for (int i = 0; i < 6000; ++i) {
        auto payload = seeds[rng() % seeds.size()];
        payload.resize(rng() % (payload.size() + 1));
        for (unsigned k = rng() % 6; k > 0 && !payload.empty(); --k) payload[rng() % payload.size()] = static_cast<char>(rng());
        auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "0050", "00000001", "00000001", "18", payload);
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, (i % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: info.fields) check(l);
    }
}

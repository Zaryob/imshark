#pragma once

// Hand-built DTLS datagrams shared by the DTLS tests: the byte layouts are RFC 6347 section 4.1 / 4.2.1 (record, handshake header,
// ClientHello, HelloVerifyRequest) and RFC 5246 (hello bodies, Certificate), written out here so nothing is produced by the code
// under test. The certificate is a P-256 certificate made with `openssl req -x509 ... -subj "/CN=dtls.example.test/O=ImShark Test"
// -addext subjectAltName=DNS:dtls.example.test,DNS:alt.example.test`.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "support.h"

namespace dtlstest {
    inline std::string be(uint64_t v, int bytes) {
        std::string s;
        for (int i = bytes - 1; i >= 0; --i) s += static_cast<char>((v >> (8 * i)) & 0xff);
        return s;
    }

    inline std::string record(uint8_t type, uint16_t version, uint16_t epoch, uint64_t seq, const std::string &body) {
        return std::string(1, static_cast<char>(type)) + be(version, 2) + be(epoch, 2) + be(seq, 6) + be(body.size(), 2) + body;
    }

    // a handshake fragment: the whole message `body` is announced, `length` bytes from `offset` are carried (npos: all)
    inline std::string handshake(uint8_t type, uint16_t messageSeq, const std::string &body, uint32_t offset = 0, size_t length = std::string::npos) {
        if (length == std::string::npos) length = body.size() - offset;
        return std::string(1, static_cast<char>(type)) + be(body.size(), 3) + be(messageSeq, 2) + be(offset, 3) + be(length, 3) + body.substr(offset, length);
    }

    inline std::string randomOf(uint8_t first) {
        std::string r;
        for (int i = 0; i < 32; ++i) r += static_cast<char>(first + i);
        return r;
    }

    inline std::string clientHelloBody(const std::string &cookie, const std::string &sni, uint8_t randomFirst = 0) {
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

    inline std::string serverHelloBody(uint16_t cipher = 0xc02f, uint8_t randomFirst = 0x80) {
        return be(0xfefd, 2) + randomOf(randomFirst) + std::string(1, '\0') + be(cipher, 2) + std::string(1, '\0') + be(0, 2);
    }

    inline std::string helloVerifyBody(const std::string &cookie) { return be(0xfefd, 2) + std::string(1, static_cast<char>(cookie.size())) + cookie; }

    inline const std::string kCertificateDer = []() {
        const std::string h =
            "308201ee30820193a003020102021457f4d156153812da9dc7f58cd69763b7803003e1300a06082a8648ce3d0403023033311a301806035504030c1164746c732e6578616d706c652e7465737431153013060355040a0c0c496d536861726b2054657374301e170d3236313030363039353230345a170d3336313030333039353230345a3033311a301806035504030c1164746c732e6578616d706c652e7465737431153013060355040a0c0c496d536861726b20546573743059301306072a8648ce3d020106082a8648ce3d03010703420004bca27af4df52ffed74a0e0c18ac9f644ab43b2202f55bf5fa3f5e75f1264a6cea9c6ad7b3f585429953f9199dca36ced654df6140e3d617f5a85c93373a5ea63a38184308181301d0603551d0e04160414d6d8f8f9804b38a1bc20873025cc11fa5739c6d5301f0603551d23041830168014d6d8f8f9804b38a1bc20873025cc11fa5739c6d5300f0603551d130101ff040530030101ff302e0603551d1104273025821164746c732e6578616d706c652e746573748210616c742e6578616d706c652e74657374300a06082a8648ce3d040302034900304602210080b447c04bd7ef0b77027b598373d0ea96b81261bfe50e2d3d99955a3d3dd7b1022100d960d75ba139583ce1683edb37e1cd4666e9e2a8a2518a0359b3c52d042bf135";
        const auto v = support::hex(h);
        return std::string(v.begin(), v.end());
    }();

    inline std::string certificateBody() { return be(kCertificateDer.size() + 3, 3) + be(kCertificateDer.size(), 3) + kCertificateDer; }

    inline std::string port(uint16_t p) {
        char text[8];
        std::snprintf(text, sizeof text, "%04x", p);
        return text;
    }

    constexpr uint16_t kClientPort = 50000, kServerPort = 4433;

    // client -> server
    inline std::vector<char> toServer(const std::string &payload, uint16_t dport = kServerPort) { return support::udpPacket("0a000001", "0a000002", port(kClientPort), port(dport), payload); }
    // server -> client
    inline std::vector<char> toClient(const std::string &payload, uint16_t sport = kServerPort) { return support::udpPacket("0a000002", "0a000001", port(sport), port(kClientPort), payload); }

    inline std::string hsRecord(uint64_t seq, const std::string &handshakes, uint16_t version = 0xfefd) { return record(22, version, 0, seq, handshakes); }

} // namespace dtlstest

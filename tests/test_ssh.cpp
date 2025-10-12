#include <gtest/gtest.h>

#include "dissect/protocols.h"
#include "filter/filter.h"
#include "support.h"

#include <random>
#include <string>

namespace {

packet::PacketInfo sshTcp(const std::string &payload, const char *sport = "c350", const char *dport = "0016") {
    // 0016 = 22 (SSH port)
    return support::parse(support::tcpPacket("0a000001", "0a000002", sport, dport, "00000001", "00000001", "18", payload));
}

bool matches(const std::string &expr, const packet::PacketInfo &pkt) {
    auto r = filter::Filter::compile(expr);
    EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
    return r.ok && r.filter.matches(pkt);
}

const packet::Field *findField(const std::vector<packet::Field> &fields, const std::string &prefix) {
    for (const auto &f : fields) {
        if (f.text.rfind(prefix, 0) == 0 || f.text.find(prefix) != std::string::npos) return &f;
        if (const auto *c = findField(f.children, prefix)) return c;
    }
    return nullptr;
}

std::string makeString(const std::string &s) {
    uint32_t len = static_cast<uint32_t>(s.size());
    std::string res;
    res.push_back(static_cast<char>((len >> 24) & 0xff));
    res.push_back(static_cast<char>((len >> 16) & 0xff));
    res.push_back(static_cast<char>((len >> 8) & 0xff));
    res.push_back(static_cast<char>(len & 0xff));
    res += s;
    return res;
}

std::string makePacket(uint8_t msgCode, const std::string &payloadData, size_t paddingLen = 8) {
    std::string inner;
    inner.push_back(static_cast<char>(msgCode));
    inner += payloadData;
    inner.append(paddingLen, '\0');

    uint32_t pktLen = static_cast<uint32_t>(1 + inner.size()); // 1 byte padding_len + inner
    std::string res;
    res.push_back(static_cast<char>((pktLen >> 24) & 0xff));
    res.push_back(static_cast<char>((pktLen >> 16) & 0xff));
    res.push_back(static_cast<char>((pktLen >> 8) & 0xff));
    res.push_back(static_cast<char>(pktLen & 0xff));
    res.push_back(static_cast<char>(paddingLen));
    res += inner;
    return res;
}

} // namespace

TEST(SshDissect, BannerExchange) {
    const std::string banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    const auto pkt = sshTcp(banner);
    EXPECT_EQ(pkt.protocol, "SSH");
    EXPECT_NE(pkt.info.find("Protocol: SSH-2.0-OpenSSH_8.9p1"), std::string::npos);
    EXPECT_EQ(pkt.app_text, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1");
    EXPECT_TRUE(matches("ssh", pkt));
    EXPECT_TRUE(matches("ssh.protocol contains \"OpenSSH\"", pkt));

    EXPECT_NE(findField(pkt.fields, "Identification String: SSH-2.0-OpenSSH_8.9p1"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Protocol Version: 2.0"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Software Version: OpenSSH_8.9p1"), nullptr);
}

TEST(SshDissect, KexInitPacket) {
    std::string kexData;
    // 16 bytes cookie
    kexData.append(16, '\x42');
    // Name lists
    kexData += makeString("curve25519-sha256,ecdh-sha2-nistp256"); // kex
    kexData += makeString("rsa-sha2-512,rsa-sha2-256");          // host key
    kexData += makeString("aes128-ctr,aes256-ctr");              // enc c->s
    kexData += makeString("aes128-ctr,aes256-ctr");              // enc s->c
    kexData += makeString("hmac-sha2-256");                       // mac c->s
    kexData += makeString("hmac-sha2-256");                       // mac s->c
    kexData += makeString("none");                                // comp c->s
    kexData += makeString("none");                                // comp s->c
    kexData += makeString("");                                    // lang c->s
    kexData += makeString("");                                    // lang s->c
    kexData.push_back('\0');                                      // first_kex_packet_follows = false
    kexData.append(4, '\0');                                      // uint32 0

    std::string packetBytes = makePacket(20, kexData, 8);
    const auto pkt = sshTcp(packetBytes);

    EXPECT_EQ(pkt.protocol, "SSH");
    EXPECT_NE(pkt.info.find("Key Exchange Init"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 20);
    EXPECT_EQ(pkt.app_text, "curve25519-sha256");
    EXPECT_EQ(pkt.app_text2, "aes128-ctr");

    EXPECT_TRUE(matches("ssh", pkt));
    EXPECT_TRUE(matches("ssh.message_code == 20", pkt));
    EXPECT_TRUE(matches("ssh.kex_algorithm == \"curve25519-sha256\"", pkt));
    EXPECT_TRUE(matches("ssh.encryption_algorithm == \"aes128-ctr\"", pkt));

    EXPECT_NE(findField(pkt.fields, "Key Exchange Init (SSH_MSG_KEXINIT)"), nullptr);
    EXPECT_NE(findField(pkt.fields, "KEX Algorithms: curve25519-sha256,ecdh-sha2-nistp256"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Server Host Key Algorithms: rsa-sha2-512,rsa-sha2-256"), nullptr);
}

TEST(SshDissect, NewKeysPacket) {
    std::string packetBytes = makePacket(21, "", 10);
    const auto pkt = sshTcp(packetBytes);

    EXPECT_EQ(pkt.protocol, "SSH");
    EXPECT_NE(pkt.info.find("New Keys"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 21);
    EXPECT_TRUE(matches("ssh", pkt));
    EXPECT_TRUE(matches("ssh.message_code == 21", pkt));
    EXPECT_NE(findField(pkt.fields, "New Keys (SSH_MSG_NEWKEYS)"), nullptr);
}

TEST(SshDissect, DhInitAndReply) {
    std::string initBytes = makePacket(30, std::string(32, '\x01'), 8);
    const auto pkt1 = sshTcp(initBytes);
    EXPECT_EQ(pkt1.protocol, "SSH");
    EXPECT_EQ(pkt1.app_type, 30);
    EXPECT_TRUE(matches("ssh.message_code == 30", pkt1));
    EXPECT_NE(findField(pkt1.fields, "Diffie-Hellman Key Exchange Init (30)"), nullptr);

    std::string replyBytes = makePacket(31, std::string(64, '\x02'), 8);
    const auto pkt2 = sshTcp(replyBytes);
    EXPECT_EQ(pkt2.protocol, "SSH");
    EXPECT_EQ(pkt2.app_type, 31);
    EXPECT_TRUE(matches("ssh.message_code == 31", pkt2));
    EXPECT_NE(findField(pkt2.fields, "Diffie-Hellman Key Exchange Reply (31)"), nullptr);
}

TEST(SshDissect, EncryptedPacket) {
    // Arbitrary encrypted payload without valid cleartext structure or exceeding available bytes
    std::string enc = std::string("\x00\x00\x01\x00\x10" "encrypted payload bytes with mac...", 40);
    const auto pkt = sshTcp(enc);
    EXPECT_EQ(pkt.protocol, "SSH");
    EXPECT_EQ(pkt.app_type, 255);
    EXPECT_TRUE(matches("ssh.encrypted", pkt));
    EXPECT_NE(findField(pkt.fields, "Encrypted packet"), nullptr);
}

TEST(SshDissect, DecodeAsNonStandardPort) {
    dissect::Registry reg = dissect::Registry::builtin();
    std::string err;
    ASSERT_TRUE(reg.decodeAs(true, 2222, "SSH", &err)) << err;

    packet::PacketParser parser(reg);
    packet::PacketInfo pkt(1);
    const std::string banner = "SSH-2.0-OpenSSH_9.0\r\n";
    auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "08ae", "00000001", "00000001", "18", banner);
    parser.parsePacket(pkt, frame, dissect::ParseMode::Full);
    EXPECT_EQ(pkt.protocol, "SSH");
    EXPECT_NE(pkt.info.find("Protocol: SSH-2.0-OpenSSH_9.0"), std::string::npos);
    EXPECT_TRUE(matches("ssh", pkt));
}

TEST(SshDissect, Fuzz) {
    std::mt19937 rng(42);
    for (int i = 0; i < 200; ++i) {
        const size_t len = rng() % 256;
        std::string trash(len, '\0');
        for (size_t j = 0; j < len; ++j) trash[j] = static_cast<char>(rng() & 0xff);
        EXPECT_NO_THROW(sshTcp(trash));
    }
}

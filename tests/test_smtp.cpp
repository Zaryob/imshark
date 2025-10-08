#include <gtest/gtest.h>

#include "dissect/protocols.h"
#include "filter/filter.h"
#include "support.h"

#include <random>
#include <string>

namespace {

packet::PacketInfo smtpTcp(const std::string &payload, const char *dport = "0019") {
    return support::parse(support::tcpPacket("0a000001", "0a000002", "c350", dport, "00000001", "00000001", "18", payload));
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

} // namespace

TEST(SmtpDissect, ServerBannerGreeting) {
    const std::string banner = "220 mail.example.com ESMTP Postfix\r\n";
    const auto pkt = smtpTcp(banner);
    EXPECT_EQ(pkt.protocol, "SMTP");
    EXPECT_EQ(pkt.info, "S: 220 mail.example.com ESMTP Postfix");
    EXPECT_EQ(pkt.app_type, 2);   // response
    EXPECT_EQ(pkt.app_code, 220); // reply code
    EXPECT_TRUE(matches("smtp", pkt));
    EXPECT_TRUE(matches("smtp.rsp", pkt));
    EXPECT_FALSE(matches("smtp.req", pkt));
    EXPECT_TRUE(matches("smtp.response.code == 220", pkt));
    EXPECT_NE(findField(pkt.fields, "Response code: 220"), nullptr);
}

TEST(SmtpDissect, MultilineEhloResponse) {
    const std::string multiline =
        "250-mail.example.org\r\n"
        "250-PIPELINING\r\n"
        "250-SIZE 10240000\r\n"
        "250-STARTTLS\r\n"
        "250 OK\r\n";
    const auto pkt = smtpTcp(multiline);
    EXPECT_EQ(pkt.protocol, "SMTP");
    EXPECT_EQ(pkt.app_code, 250);
    EXPECT_TRUE(matches("smtp.rsp", pkt));
    EXPECT_TRUE(matches("smtp.response.code == 250", pkt));

    const auto *layer = findField(pkt.fields, "Simple Mail Transfer Protocol");
    ASSERT_NE(layer, nullptr);
    EXPECT_NE(findField(layer->children, "Response: 250-STARTTLS"), nullptr);
    EXPECT_NE(findField(layer->children, "Response: 250 OK"), nullptr);
    EXPECT_NE(findField(layer->children, "more lines to follow (-)"), nullptr);
    EXPECT_NE(findField(layer->children, "end of response ( )"), nullptr);
}

TEST(SmtpDissect, MailFromAndRcptToCommands) {
    const auto pMail = smtpTcp("MAIL FROM:<alice@example.org>\r\n");
    EXPECT_EQ(pMail.protocol, "SMTP");
    EXPECT_EQ(pMail.info, "C: MAIL FROM:<alice@example.org>");
    EXPECT_EQ(pMail.app_type, 1); // command
    EXPECT_EQ(pMail.app_text, "MAIL FROM:");
    EXPECT_EQ(pMail.app_text2, "alice@example.org");
    EXPECT_TRUE(matches("smtp.req", pMail));
    EXPECT_TRUE(matches("smtp.command == \"MAIL FROM:\"", pMail));
    EXPECT_TRUE(matches("smtp.param == \"alice@example.org\"", pMail));

    const auto pRcpt = smtpTcp("RCPT TO:<bob@example.com>\r\n");
    EXPECT_EQ(pRcpt.info, "C: RCPT TO:<bob@example.com>");
    EXPECT_EQ(pRcpt.app_text, "RCPT TO:");
    EXPECT_EQ(pRcpt.app_text2, "bob@example.com");
    EXPECT_TRUE(matches("smtp.param == \"bob@example.com\"", pRcpt));
}

TEST(SmtpDissect, DataModeAndHeaders) {
    const auto pData = smtpTcp("DATA\r\n");
    EXPECT_EQ(pData.info, "C: DATA");
    EXPECT_TRUE(matches("smtp.command == \"DATA\"", pData));

    const auto p354 = smtpTcp("354 Start mail input; end with <CRLF>.<CRLF>\r\n");
    EXPECT_EQ(p354.info, "S: 354 Start mail input; end with <CRLF>.<CRLF>");
    EXPECT_TRUE(matches("smtp.response.code == 354", p354));

    const std::string body =
        "From: Alice <alice@example.org>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Project Status\r\n"
        "\r\n"
        "Hello Bob,\r\n"
        "Everything is on schedule.\r\n"
        ".\r\n";
    const auto pBody = smtpTcp(body);
    EXPECT_EQ(pBody.protocol, "SMTP");
    EXPECT_NE(findField(pBody.fields, "Header: From: Alice <alice@example.org>"), nullptr);
    EXPECT_NE(findField(pBody.fields, "Header: Subject: Project Status"), nullptr);
    EXPECT_NE(findField(pBody.fields, "End of message data (.)"), nullptr);
}

TEST(SmtpDissect, StarttlsAndSubmissionPort) {
    // Port 587 (0x024b)
    const auto pSub = smtpTcp("STARTTLS\r\n", "024b");
    EXPECT_EQ(pSub.protocol, "SMTP");
    EXPECT_EQ(pSub.info, "C: STARTTLS");
    EXPECT_TRUE(matches("smtp.command == \"STARTTLS\"", pSub));

    const auto pReady = smtpTcp("220 2.0.0 Ready to start TLS\r\n", "024b");
    EXPECT_EQ(pReady.protocol, "SMTP");
    EXPECT_EQ(pReady.info, "S: 220 2.0.0 Ready to start TLS");
    EXPECT_TRUE(matches("smtp.response.code == 220", pReady));
}

TEST(SmtpDissect, FuzzResistance) {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_int_distribution<size_t> lenDist(1, 200);

    for (int iter = 0; iter < 1000; ++iter) {
        const size_t len = lenDist(rng);
        std::string payload;
        payload.reserve(len);
        for (size_t b = 0; b < len; ++b) {
            payload.push_back(static_cast<char>(byteDist(rng)));
        }

        const auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "0019", "00000001", "00000001", "18", payload);
        const auto pkt = support::parse(frame);
        EXPECT_EQ(pkt.protocol, "SMTP");
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c : f.children) check(c);
        };
        for (const auto &l : pkt.fields) check(l);
    }
}

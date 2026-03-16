// LDAP (RFC 4511): messages built by an independent BER encoder (Python, stdlib only) and cross-checked with
//   /opt/homebrew/opt/openssl@3/bin/openssl asn1parse -inform DER
// e.g. for kSearch:  0:d=0 hl=2 l=81 cons: SEQUENCE / 2: INTEGER :02 / 5: appl [ 3 ] l=76 / OCTET STRING :dc=example,dc=com /
//   ENUMERATED :02 / ENUMERATED :00 / INTEGER :00 / INTEGER :00 / BOOLEAN :0 / cont [ 0 ] { cont [ 3 ] { objectClass, person },
//   cont [ 4 ] { cn, SEQUENCE { cont [ 0 ] } } } / SEQUENCE { OCTET STRING :cn }
// StartTLS: the requestName / responseName are the text OID of RFC 4511 4.14 (LDAPOID is an OCTET STRING).
#include <gtest/gtest.h>

#include <functional>

#include <core.h>
#include <dissect/ldap.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kBind = bytes("302c0201016027020103041a636e3d61646d696e2c64633d6578616d706c652c" "64633d636f6d8006736563726574");
    const std::string kBindResp = bytes("300c02010161070a010004000400");
    const std::string kSearch = bytes("3051020102634c041164633d6578616d706c652c64633d636f6d0a01020a0100" "020100020100010100a022a315040b6f626a656374436c617373040670657273" "6f6ea4090402636e300380016130040402636e");
    const std::string kEntry = bytes("3032020102642d041a636e3d416c6963652c64633d6578616d706c652c64633d" "636f6d300f300d0402636e31070405416c696365");
    const std::string kDone = bytes("300c02010265070a010004000400");
    const std::string kNoSuch = bytes("302b02010565260a0120041164633d6578616d706c652c64633d636f6d040e6e" "6f2073756368206f626a656374");
    const std::string kStartTls = bytes("301d02010377188016312e332e362e312e342e312e313436362e3230303337");
    const std::string kStartTlsOk = bytes("3024020103781f0a0100040004008a16312e332e362e312e342e312e31343636" "2e3230303337");
    const std::string kUnbind = bytes("30050201044200");
    const std::string kAbandon = bytes("3006020105500103");
    const std::string kDel = bytes("301b0201064a16636e3d782c64633d6578616d706c652c64633d636f6d");
    const std::string kSaslBind = bytes("3014020107600f0201030400a3080406475353415049");

    const std::string kClientHello = bytes("160301" "0004" "01000000");
    const std::string kServerHello = bytes("160303" "0004" "02000000");
    const std::string kAppData = bytes("170303" "0010" "00112233445566778899aabbccddeeff");

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr << ": " << f.error.message;
        return f.ok && f.filter.matches(p);
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }
}

TEST(Ldap, BindRequestShowsTheNameAndNeverThePassword) {
    Flow flow(50000, 389, "ldap_bind");
    flow.client(kBind);
    flow.load();
    const auto &p = flow.packets().at(0);
    EXPECT_EQ(p.protocol, "LDAP");
    EXPECT_EQ(p.app_stream, 1u);   // the message id lives in app_stream, tcp_pdu_start stays TCP bookkeeping
    EXPECT_EQ(p.app_type, 0u);
    EXPECT_EQ(p.app_text, "cn=admin,dc=example,dc=com");
    EXPECT_EQ(p.info, "BindRequest (MsgID=1, name=\"cn=admin,dc=example,dc=com\", simple)");
    EXPECT_TRUE(matches("ldap && ldap.message_id == 1 && ldap.protocol_op == 0 && ldap.name == \"cn=admin,dc=example,dc=com\"", p));
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Authentication: simple (the password is not shown)"), nullptr);
    std::string all;
    std::function<void(const std::vector<packet::Field> &)> walk = [&](const std::vector<packet::Field> &v) { for (auto &f: v) { all += f.text + "\n"; walk(f.children); } };
    walk(d.fields);
    EXPECT_EQ(all.find("secret"), std::string::npos);
    EXPECT_EQ(all.find("736563726574"), std::string::npos);
}

TEST(Ldap, SaslBindNamesTheMechanism) {
    Flow flow(50000, 389, "ldap_sasl");
    flow.client(kSaslBind);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "BindRequest (MsgID=7, name=\"<anonymous>\", SASL GSSAPI)");
}

TEST(Ldap, SearchRequestShowsBaseScopeAndTheFilterInRfc4515Form) {
    Flow flow(50000, 389, "ldap_search");
    flow.client(kSearch);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.info, "SearchRequest (MsgID=2, base=\"dc=example,dc=com\", scope=wholeSubtree, filter=(&(objectClass=person)(cn=a*)))");
    EXPECT_EQ(p.app_type, 3u);
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Filter: (&(objectClass=person)(cn=a*))"), nullptr);
    EXPECT_NE(find(d.fields, "Scope: wholeSubtree (2)"), nullptr);
}

TEST(Ldap, ResponsesCarryTheResultCode) {
    Flow flow(50000, 389, "ldap_results");
    flow.client(kBind).server(kBindResp).client(kSearch).server(kEntry).server(kDone).client(kDel).server(kNoSuch);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "BindResponse (MsgID=1, result=success)");
    EXPECT_TRUE(matches("ldap.result_code == 0 && ldap.protocol_op == 1", k[1]));
    EXPECT_EQ(k[3].info, "SearchResultEntry (MsgID=2, entry=\"cn=Alice,dc=example,dc=com\")");
    EXPECT_FALSE(matches("ldap.result_code == 0", k[3])) << "an entry has no result code";
    EXPECT_EQ(k[4].info, "SearchResultDone (MsgID=2, result=success)");
    EXPECT_EQ(k[5].info, "DelRequest (MsgID=6, entry=\"cn=x,dc=example,dc=com\")");
    EXPECT_EQ(k[6].info, "SearchResultDone (MsgID=5, result=noSuchObject, \"no such object\")");
    EXPECT_TRUE(matches("ldap.result_code == 32", k[6]));
    EXPECT_EQ(find(flow.details(6).fields, "Matched DN: dc=example,dc=com") != nullptr, true);
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, UnbindAndAbandon) {
    Flow flow(50000, 389, "ldap_unbind");
    flow.client(kAbandon).client(kUnbind);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "AbandonRequest (MsgID=5, abandon MsgID=3)");
    EXPECT_EQ(flow.packets()[1].info, "UnbindRequest (MsgID=4)");
}

TEST(Ldap, AMessageSplitOverSegmentsIsReassembledAndKeepsItsMessageId) {
    Flow flow(50000, 389, "ldap_split");
    flow.client(kSearch.substr(0, 4)).client(kSearch.substr(4, 30)).client(kSearch.substr(34));
    flow.load();
    const auto &k = flow.packets();
    ASSERT_EQ(k.size(), 3u);
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_NE(k[1].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[1].info;
    EXPECT_EQ(k[2].protocol, "LDAP");
    EXPECT_EQ(k[2].app_stream, 2u) << "the message id, not the TCP sequence number of the message";
    EXPECT_TRUE(matches("ldap.message_id == 2 && ldap.protocol_op == 3", k[2]));
    EXPECT_EQ(k[2].tcp_pdu_state, 2u);
    EXPECT_EQ(k[2].tcp_pdu_start, 0u);   // the TCP reassembly bookkeeping is untouched
    EXPECT_EQ(k[2].info.rfind("SearchRequest (MsgID=2", 0), 0u);
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, PipelinedMessagesInOneSegmentAreAllShownAndReplayEqualsTheLoadPass) {
    Flow flow(50000, 389, "ldap_pipe");
    flow.client(kBind + kSearch + kUnbind).server(kBindResp + kEntry + kDone);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "LDAP");
    EXPECT_EQ(k[0].app_stream, 1u);
    EXPECT_NE(k[0].info.find("BindRequest (MsgID=1"), std::string::npos);
    EXPECT_NE(k[0].info.find(", SearchRequest (MsgID=2"), std::string::npos);
    EXPECT_NE(k[0].info.find(", UnbindRequest (MsgID=4)"), std::string::npos);
    EXPECT_EQ(k[0].tcp_pdu_state, 3u);
    EXPECT_EQ(k[0].tcp_pdu_start, 0u);   // TCP bookkeeping: where the first message starts, not a message id
    flow.expectReplayEqualsLoad();
}

TEST(LdapFramer, ReturnsNeedMoreWithTheTotalForAPartialMessage) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameLdap(s.data(), s.size()); };
    EXPECT_EQ(frame(kSearch.substr(0, 12)).kind, K::NeedMore);   // the audit's reproduction: a 12-byte prefix was Reject
    EXPECT_EQ(frame(kSearch.substr(0, 12)).length, kSearch.size()) << "NeedMore carries the total";
    EXPECT_EQ(frame(bytes("30840000")).kind, K::NeedMore);          // long-form length cut inside its length bytes
    EXPECT_EQ(frame(bytes("30")).kind, K::NeedMore);
    EXPECT_EQ(frame(kSearch.substr(0, 40)).kind, K::NeedMore);
    const auto whole = frame(kSearch + kBind);
    EXPECT_EQ(whole.kind, K::Complete);
    EXPECT_EQ(whole.length, kSearch.size());
    EXPECT_EQ(frame(kBind).length, kBind.size());
    EXPECT_EQ(frame(bytes("3084000001000201")).kind, K::NeedMore) << "a 256 byte message that has not arrived yet";
}

TEST(LdapFramer, RejectsWhatIsNotAnLdapMessage) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameLdap(s.data(), s.size()); };
    EXPECT_EQ(frame(bytes("3080020101")).kind, K::Reject) << "indefinite length is not LDAP (RFC 4511 5.1)";
    EXPECT_EQ(frame(bytes("3085000000000100")).kind, K::Reject) << "more than four length bytes";
    EXPECT_EQ(frame(bytes("3084ffffffff0201")).kind, K::Reject) << "bigger than the stream table buffers";
    EXPECT_EQ(frame(bytes("1603010004010000")).kind, K::Reject) << "a TLS record";
    EXPECT_EQ(frame(bytes("3003040100")).kind, K::Reject) << "the first element is not the message id";
    EXPECT_EQ(frame(bytes("3000")).kind, K::Reject) << "empty message";
}

TEST(Ldap, StartTlsSwitchesTheConnectionToTls) {
    Flow flow(50000, 389, "ldap_starttls");
    flow.client(kBind).server(kBindResp).client(kStartTls).server(kStartTlsOk).client(kClientHello).server(kServerHello).client(kAppData);
    flow.load();
    const auto &k = flow.packets();
    ASSERT_EQ(k.size(), 7u);
    EXPECT_EQ(k[2].info, "ExtendedRequest (MsgID=3, StartTLS)");
    EXPECT_EQ(k[3].info, "ExtendedResponse (MsgID=3, result=success, StartTLS) - TLS follows");
    EXPECT_TRUE(matches("ldap.extended_name == \"1.3.6.1.4.1.1466.20037\" && ldap.result_code == 0", k[3]));
    EXPECT_EQ(k[4].protocol, "TLS");
    EXPECT_EQ(k[4].info, "Client Hello");
    EXPECT_EQ(k[5].protocol, "TLS");
    EXPECT_EQ(k[6].protocol, "TLS");
    EXPECT_EQ(k[0].protocol, "LDAP") << "the messages before the switch stay LDAP";
    flow.expectReplayEqualsLoad();   // Replay reads the stored switch: the same answer for every packet
}

TEST(Ldap, EncryptedBytesAfterStartTlsAreNotMisreadAsLdap) {
    Flow flow(50000, 389, "ldap_starttls_junk");
    flow.client(kStartTls).server(kStartTlsOk).client(bytes("99aabbccddeeff00112233445566778899aabbcc")).server(bytes("0102030405060708090a0b0c"));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[2].protocol, "TCP") << k[2].info;
    EXPECT_EQ(k[3].protocol, "TCP") << k[3].info;
    EXPECT_FALSE(matches("malformed", k[2]));
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, AFailedStartTlsOrAPlainBindKeepsTheConnectionLdap) {
    Flow flow(50000, 389, "ldap_starttls_refused");
    const std::string refused = bytes("3024020103781f0a0134" "04000400" "8a16312e332e362e312e342e312e313436362e3230303337");   // result 52 unavailable
    flow.client(kStartTls).server(refused).client(kBind);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "ExtendedResponse (MsgID=3, result=unavailable, StartTLS)");
    EXPECT_EQ(k[2].protocol, "LDAP");
}

TEST(Ldap, TextFromThePacketIsPrintableAndBounded) {
    // DN "cn=a<SOH>b\n" + 400 'x'
    std::string dn = "cn=a\x01" "b\n" + std::string(400, 'x');
    std::string body = bytes("020103") + bytes("0482") + std::string(1, static_cast<char>(dn.size() >> 8)) + std::string(1, static_cast<char>(dn.size() & 0xff)) + dn + bytes("8000");
    std::string op = bytes("6082") + std::string(1, static_cast<char>(body.size() >> 8)) + std::string(1, static_cast<char>(body.size() & 0xff)) + body;
    std::string msg = bytes("020109") + op;
    msg = bytes("3082") + std::string(1, static_cast<char>(msg.size() >> 8)) + std::string(1, static_cast<char>(msg.size() & 0xff)) + msg;
    Flow flow(50000, 389, "ldap_text");
    flow.client(msg);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.app_text.rfind("cn=a?b?xxx", 0), 0u) << p.app_text;
    EXPECT_LE(p.app_text.size(), 203u);
    EXPECT_EQ(p.info.find('\n'), std::string::npos);
}

TEST(Ldap, ATruncatedCaptureIsReadAsFarAsItGoesAndStaysInsideTheFrame) {
    for (const std::string *m: {&kBind, &kSearch, &kEntry, &kStartTlsOk, &kNoSuch, &kSaslBind, &kDel, &kAbandon, &kUnbind}) {
        appflow::sweepPayload(*m, 389, 0x1d4b);
        appflow::sweepPayload(*m, 636, 0x2e5c);
    }
}

TEST(Ldap, TheSameBytesOnAnotherPortAreNotLdapUnlessAskedFor) {
    Flow flow(50000, 8080, "ldap_other_port");
    flow.client(kBind);
    flow.load();
    EXPECT_NE(flow.packets()[0].protocol, "LDAP");
}

TEST(Ldap, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"LDAP"});
}

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

    // Operations added in v1.3, built by the same independent BER encoder and checked with asn1parse, e.g. kModify:
    //   appl [ 6 ] { OCTET STRING :cn=Alice,dc=example,dc=com, SEQUENCE { SEQUENCE { ENUMERATED :02, SEQUENCE { OCTET STRING :mail,
    //   SET { OCTET STRING :alice@corp.example } } }, SEQUENCE { ENUMERATED :00, SEQUENCE { description, SET { one, two } } },
    //   SEQUENCE { ENUMERATED :01, SEQUENCE { telephoneNumber, SET {} } }, SEQUENCE { ENUMERATED :02, SEQUENCE { userPassword, SET { ... } } } } }
    // kSearchFull: filter cont [ 0 ] (and) { cont [ 3 ] objectClass=person, cont [ 1 ] (or) { cont [ 4 ] cn SEQUENCE { cont [ 0 ] Al, cont [ 1 ] ic,
    //   cont [ 2 ] e }, cont [ 5 ] uid 100, cont [ 6 ] uid 200, cont [ 8 ] sn smyth }, cont [ 2 ] { cont [ 7 ] mail }, cont [ 3 ] description a*b(c)\d,
    //   cont [ 9 ] { cont [ 1 ] 1.2.840.113556.1.4.803, cont [ 2 ] userAccountControl, cont [ 3 ] 2, cont [ 4 ] ff }, ... }, SEQUENCE { cn, mail },
    //   then the message's cont [ 0 ] controls: SEQUENCE { OCTET STRING :1.2.840.113556.1.4.319 (LDAPOID is text), BOOLEAN :255, OCTET STRING 30050201640400 }, SEQUENCE { ...801, BOOLEAN :0, 3003020107 }
    // kSaslSpnego: appl [ 0 ] { INTEGER :03, OCTET STRING (empty), cont [ 3 ] { OCTET STRING :GSS-SPNEGO, OCTET STRING [HEX DUMP]:6081D006062B0601050502A0... } }
    //   (the credentials are the SPNEGO token of test_spnego.cpp: a NegTokenInit whose mechToken is a GSS-API Kerberos AP-REQ for cifs/files.corp.com)
    const std::string kSearchFull = bytes("3082015302010263820100041164633d6578616d706c652c64633d636f6d0a01"
        "020a0100020100020100010100a081cfa315040b6f626a656374436c61737304"
        "06706572736f6ea138a4110402636e300b8002416c81026963820165a50a0403"
        "7569640403313030a60a04037569640403323030a80b0402736e0405736d7974"
        "68a20687046d61696ca317040b6465736372697074696f6e0408612a62286329"
        "5c64a9328116312e322e3834302e3131333535362e312e342e38303382127573"
        "65724163636f756e74436f6e74726f6c8301328401ffa40e04057469746c6530"
        "0581036d6964a317040c7573657250617373776f7264040768756e7465723230"
        "0a0402636e04046d61696ca04a30240416312e322e3834302e3131333535362e"
        "312e342e3331390101ff04073005020164040030220416312e322e3834302e31"
        "31333535362e312e342e38303101010004053003020107");
    const std::string kEntryFull = bytes("3081cd0201026481c7041a636e3d416c6963652c64633d6578616d706c652c64"
        "633d636f6d3081a8300d0402636e31070405416c696365302b040b6f626a6563"
        "74436c617373311c0403746f700406706572736f6e040d696e65744f72675065"
        "72736f6e3018040c7573657250617373776f7264310804067333637233743022"
        "04096a70656750686f746f31150413ffd8ffe000104a46494600010203040506"
        "0708301b04046d61696c31130411616c696365406578616d706c652e636f6d30"
        "0f040b6465736372697074696f6e3100");
    const std::string kModify = bytes("3081a302010366819d041a636e3d416c6963652c64633d6578616d706c652c64"
        "633d636f6d307f30210a0102301c04046d61696c31140412616c69636540636f"
        "72702e6578616d706c65301e0a01003019040b6465736372697074696f6e310a"
        "04036f6e65040374776f30180a01013013040f74656c6570686f6e654e756d62"
        "6572310030200a0102301b040c7573657250617373776f7264310b04096e6577"
        "736563726574");
    const std::string kAdd = bytes("307902010468740418636e3d426f622c64633d6578616d706c652c64633d636f"
        "6d3058301c040b6f626a656374436c617373310d0403746f700406706572736f"
        "6e300b0402636e31050403426f62300f0402736e310904074275696c64657230"
        "1a040c7573657250617373776f7264310a0408626f627370617373");
    const std::string kModDn = bytes("304a0201056c450418636e3d426f622c64633d6578616d706c652c64633d636f"
        "6d0409636e3d526f626572740101ff801b6f753d70656f706c652c64633d6578"
        "616d706c652c64633d636f6d");
    const std::string kCompare = bytes("30380201066e330418636e3d426f622c64633d6578616d706c652c64633d636f"
        "6d301704046d61696c040f626f62406578616d706c652e636f6d");
    const std::string kComparePw = bytes("303a0201066e350418636e3d426f622c64633d6578616d706c652c64633d636f"
        "6d3019040c7573657250617373776f72640409746f70736563726574");
    const std::string kCompareTrue = bytes("300c0201066f070a010604000400");
    const std::string kRef = bytes("304c0201027347042a6c6461703a2f2f6f746865722e6578616d706c652e636f"
        "6d2f64633d6578616d706c652c64633d636f6d04196c6461703a2f2f74686972"
        "642e6578616d706c652e636f6d2f");
    const std::string kDoneRef = bytes("3043020102653e0a010a04000409736565206f74686572a32c042a6c6461703a"
        "2f2f6f746865722e6578616d706c652e636f6d2f64633d6578616d706c652c64"
        "633d636f6d");
    const std::string kSaslSpnego = bytes("3081f00201086081ea0201030400a381e2040a4753532d53504e45474f0481d3"
        "6081d006062b0601050502a081c53081c2a024302206092a864882f712010202"
        "06092a864886f712010202060a2b06010401823702020aa28199048196608193"
        "06092a864886f71201020201006e8183308180a003020105a10302010ea20703"
        "050020000000a3526150304ea003020105a10a1b08434f52502e434f4da22130"
        "1fa003020102a11830161b04636966731b0e66696c65732e636f72702e636f6d"
        "a3183016a003020112a103020103a20a0408cccccccccccccccca4173015a003"
        "020112a20e040cffffffffffffffffffffffff");
    const std::string kSaslGssapi = bytes("3081af0201096081a90201030400a381a1040647535341504904819660819306"
        "092a864886f71201020201006e8183308180a003020105a10302010ea2070305"
        "0020000000a3526150304ea003020105a10a1b08434f52502e434f4da221301f"
        "a003020102a11830161b04636966731b0e66696c65732e636f72702e636f6da3"
        "183016a003020112a103020103a20a0408cccccccccccccccca4173015a00302"
        "0112a20e040cffffffffffffffffffffffff");
    const std::string kSaslPlain = bytes("302702010a60220201030400a31b0405504c41494e0412006361726f6c007077"
        "2d6f662d6361726f6c");
    const std::string kBindRespSasl = bytes("305c02010861570a010004000400874ea14c304aa0030a0100a10b06092a8648"
        "86f712010202a2360434603206092a864886f71201020202006f233021a00302"
        "0105a10302010fa2153013a003020112a20c040a11111111111111111111");
    const std::string kBindRespProgress = bytes("304902010861440a010e04000400873ba1393037a0030a0101a10c060a2b0601"
        "0401823702020aa22204204e544c4d5353500002000000000000000000000000"
        "0000000000000000000000");
    const std::string kWhoami = bytes("301e02010b77198017312e332e362e312e342e312e343230332e312e31312e33");
    const std::string kPwMod = bytes("303402010c772f8017312e332e362e312e342e312e343230332e312e31312e31"
        "8114301281076f6c647061737382076e657770617373");
    const std::string kInter = bytes("302302010d791e8018312e332e362e312e342e312e343230332e312e392e312e"
        "3481020102");
    const std::string kRespCtl = bytes("303402010265070a010004000400a02630240416312e322e3834302e31313335"
        "35362e312e342e333139040a30080201000403010203");

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
    EXPECT_NE(find(d.fields, "Authentication: simple (password: 6 bytes, not shown)"), nullptr);
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

namespace {
    std::string treeText(const std::vector<packet::Field> &fields) {
        std::string all;
        std::function<void(const std::vector<packet::Field> &)> walk = [&](const std::vector<packet::Field> &v) { for (auto &f: v) { all += f.text + "\n"; walk(f.children); } };
        walk(fields);
        return all;
    }
}

TEST(Ldap, SearchRequestRendersEveryFilterKindInRfc4515FormWithEscapesAndHidesCredentials) {
    Flow flow(50000, 389, "ldap_filter");
    flow.client(kSearchFull);
    flow.load();
    const auto d = flow.details(0);
    const std::string expected = "(&(objectClass=person)(|(cn=Al*ic*e)(uid>=100)(uid<=200)(sn~=smyth))(!(mail=*))(description=a\\2ab\\28c\\29\\5cd)"
                                 "(userAccountControl:dn:1.2.840.113556.1.4.803:=2)(title=*mid*)(userPassword=<hidden>))";
    EXPECT_NE(find(d.fields, "Filter: " + expected), nullptr) << treeText(d.fields);
    EXPECT_EQ(treeText(d.fields).find("hunter2"), std::string::npos);
    EXPECT_NE(find(d.fields, "Attributes (2): cn, mail"), nullptr);
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.info.rfind("SearchRequest (MsgID=2, base=\"dc=example,dc=com\", scope=wholeSubtree, filter=(&(objectClass=person)(|(cn=Al*ic*e)", 0), 0u) << p.info;
    EXPECT_EQ(p.info.find("hunter2"), std::string::npos);
    EXPECT_LE(p.info.size(), 260u) << "the filter in the Info column is cut";
}

TEST(Ldap, ControlsAreListedWithTheirNamesCriticalityAndPagedResultsValue) {
    Flow flow(50000, 389, "ldap_controls");
    flow.client(kSearchFull).server(kRespCtl);
    flow.load();
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Controls"), nullptr);
    EXPECT_NE(find(d.fields, "Control: 1.2.840.113556.1.4.319 (Paged Results)"), nullptr);
    EXPECT_NE(find(d.fields, "Criticality: true"), nullptr);
    EXPECT_NE(find(d.fields, "Size: 100"), nullptr);
    EXPECT_NE(find(d.fields, "Cookie: 0 bytes"), nullptr);
    EXPECT_NE(find(d.fields, "Control: 1.2.840.113556.1.4.801 (SD Flags)"), nullptr);
    EXPECT_NE(find(d.fields, "Criticality: false"), nullptr);
    const auto r = flow.details(1);
    EXPECT_NE(find(r.fields, "Control: 1.2.840.113556.1.4.319 (Paged Results)"), nullptr);
    EXPECT_NE(find(r.fields, "Cookie: 3 bytes"), nullptr);
    EXPECT_EQ(flow.packets()[1].info, "SearchResultDone (MsgID=2, result=success)");
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, SearchResultEntryShowsAttributesAndValuesButNotCredentials) {
    Flow flow(50000, 389, "ldap_entry");
    flow.server(kEntryFull);
    flow.load();
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Attributes: 6"), nullptr) << treeText(d.fields);
    EXPECT_NE(find(d.fields, "cn: Alice"), nullptr);
    EXPECT_NE(find(d.fields, "objectClass (3 values)"), nullptr);
    EXPECT_NE(find(d.fields, "inetOrgPerson"), nullptr);
    EXPECT_NE(find(d.fields, "mail: alice@example.com"), nullptr);
    EXPECT_NE(find(d.fields, "description (no values)"), nullptr);
    EXPECT_NE(find(d.fields, "userPassword: <hidden, 6 bytes>"), nullptr);
    EXPECT_EQ(treeText(d.fields).find("s3cr3t"), std::string::npos);
    EXPECT_NE(find(d.fields, "jpegPhoto: 0xffd8ffe000104a464946000102030405... (19 bytes)"), nullptr) << "binary values: hex preview and length";
    EXPECT_EQ(flow.packets()[0].info, "SearchResultEntry (MsgID=2, entry=\"cn=Alice,dc=example,dc=com\")");
}

TEST(Ldap, ModifyShowsEachChangeAndHidesPasswordValues) {
    Flow flow(50000, 389, "ldap_modify");
    flow.client(kModify);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.info, "ModifyRequest (MsgID=3, entry=\"cn=Alice,dc=example,dc=com\", replace mail, add description, delete telephoneNumber, replace userPassword)");
    EXPECT_EQ(p.app_text, "cn=Alice,dc=example,dc=com");
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Changes: 4"), nullptr) << treeText(d.fields);
    EXPECT_NE(find(d.fields, "Change: replace mail"), nullptr);
    EXPECT_NE(find(d.fields, "mail: alice@corp.example"), nullptr);
    EXPECT_NE(find(d.fields, "Change: add description"), nullptr);
    EXPECT_NE(find(d.fields, "description (2 values)"), nullptr);
    EXPECT_NE(find(d.fields, "Change: delete telephoneNumber"), nullptr);
    EXPECT_NE(find(d.fields, "userPassword: <hidden, 9 bytes>"), nullptr);
    EXPECT_EQ(treeText(d.fields).find("newsecret"), std::string::npos);
}

TEST(Ldap, AddModDnCompareAndTheirResponses) {
    Flow flow(50000, 389, "ldap_other_ops");
    flow.client(kAdd).client(kModDn).client(kCompare).client(kComparePw).server(kCompareTrue).server(kRef).server(kDoneRef);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "AddRequest (MsgID=4, entry=\"cn=Bob,dc=example,dc=com\", attrs=objectClass,cn,sn,userPassword)");
    const auto add = flow.details(0);
    EXPECT_NE(find(add.fields, "Attributes: 4"), nullptr);
    EXPECT_NE(find(add.fields, "sn: Builder"), nullptr);
    EXPECT_NE(find(add.fields, "userPassword: <hidden, 8 bytes>"), nullptr);
    EXPECT_EQ(treeText(add.fields).find("bobspass"), std::string::npos);
    EXPECT_EQ(k[1].info, "ModDNRequest (MsgID=5, entry=\"cn=Bob,dc=example,dc=com\", newrdn=cn=Robert, newsuperior=ou=people,dc=example,dc=com)") << "op 12 is ModifyDNRequest";
    EXPECT_EQ(k[2].info, "CompareRequest (MsgID=6, entry=\"cn=Bob,dc=example,dc=com\", mail=bob@example.com)");
    const auto cmp = flow.details(2);
    EXPECT_NE(find(cmp.fields, "Assertion: mail = bob@example.com"), nullptr);
    EXPECT_EQ(k[3].info, "CompareRequest (MsgID=6, entry=\"cn=Bob,dc=example,dc=com\", userPassword=<hidden, 9 bytes>)");
    EXPECT_EQ(k[4].info, "CompareResponse (MsgID=6, result=compareTrue)");
    EXPECT_TRUE(matches("ldap.result_code == 6 && ldap.protocol_op == 15", k[4]));
    EXPECT_EQ(k[5].info, "SearchResultReference (MsgID=2, uri=ldap://other.example.com/dc=example,dc=com)");
    EXPECT_NE(find(flow.details(5).fields, "URI: ldap://third.example.com/"), nullptr);
    EXPECT_EQ(k[6].info, "SearchResultDone (MsgID=2, result=referral, \"see other\", referral=ldap://other.example.com/dc=example,dc=com)");
    EXPECT_NE(find(flow.details(6).fields, "Referral"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, SaslBindsShowTheMechanismAndDecodeGssApiTokens) {
    Flow flow(50000, 389, "ldap_sasl_tokens");
    flow.client(kSaslSpnego).server(kBindRespProgress).client(kSaslGssapi).server(kBindRespSasl).client(kSaslPlain);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "BindRequest (MsgID=8, name=\"<anonymous>\", SASL GSS-SPNEGO, SPNEGO NegTokenInit [Kerberos 5 (MS), Kerberos 5, NTLMSSP] > AP-REQ sname=cifs/files.corp.com realm=CORP.COM)");
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Authentication: SASL GSS-SPNEGO"), nullptr);
    EXPECT_NE(find(d.fields, "Mechanism: GSS-SPNEGO"), nullptr);
    EXPECT_NE(find(d.fields, "Credentials (211 bytes)"), nullptr);
    EXPECT_NE(find(d.fields, "Simple Protected Negotiation: negTokenInit"), nullptr);
    EXPECT_NE(find(d.fields, "Kerberos (AP-REQ)"), nullptr);
    EXPECT_EQ(k[1].info, "BindResponse (MsgID=8, result=saslBindInProgress, SPNEGO NegTokenResp accept-incomplete > NTLMSSP_CHALLENGE)");
    EXPECT_NE(find(flow.details(1).fields, "Server SASL Credentials ("), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "negState: accept-incomplete (1)"), nullptr);
    EXPECT_EQ(k[2].info, "BindRequest (MsgID=9, name=\"<anonymous>\", SASL GSSAPI, AP-REQ sname=cifs/files.corp.com realm=CORP.COM)");
    EXPECT_EQ(k[3].info, "BindResponse (MsgID=8, result=success, SPNEGO NegTokenResp accept-completed > AP-REP)");
    // PLAIN carries the password: only the size is shown
    EXPECT_EQ(k[4].info, "BindRequest (MsgID=10, name=\"<anonymous>\", SASL PLAIN, token 18 bytes)");
    EXPECT_EQ(treeText(flow.details(4).fields).find("pw-of-carol"), std::string::npos);
    EXPECT_EQ(treeText(flow.details(4).fields).find("carol"), std::string::npos);
    flow.expectReplayEqualsLoad();
}

TEST(Ldap, ExtendedOperationsNameTheOperationAndNeverTheValue) {
    Flow flow(50000, 389, "ldap_extended");
    flow.client(kWhoami).client(kPwMod).server(kInter);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "ExtendedRequest (MsgID=11, name=1.3.6.1.4.1.4203.1.11.3)");
    EXPECT_NE(find(flow.details(0).fields, "Request Name: 1.3.6.1.4.1.4203.1.11.3 (Who am I?)"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "Request Name: 1.3.6.1.4.1.4203.1.11.1 (Password Modify)"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "Request Value ("), nullptr);
    EXPECT_EQ(treeText(flow.details(1).fields).find("oldpass"), std::string::npos);
    EXPECT_EQ(treeText(flow.details(1).fields).find("newpass"), std::string::npos);
    EXPECT_TRUE(matches("ldap.extended_name == \"1.3.6.1.4.1.4203.1.11.1\"", k[1]));
    EXPECT_EQ(k[2].info, "IntermediateResponse (MsgID=13, name=1.3.6.1.4.1.4203.1.9.1.4)");
}

TEST(Ldap, TheGlobalCatalogPortsAreLdap) {
    for (uint16_t port: {3268, 3269}) {
        Flow flow(50000, port, "ldap_gc");
        flow.client(kBind).server(kBindResp).client(kSearchFull);
        flow.load();
        EXPECT_EQ(flow.packets()[0].protocol, "LDAP") << port;
        EXPECT_EQ(flow.packets()[2].info.rfind("SearchRequest (MsgID=2", 0), 0u) << port;
        flow.expectReplayEqualsLoad();
    }
}

TEST(Ldap, NewOperationsStayInsideTheFrameWhenCutOrMutated) {
    for (const std::string *m: {&kSearchFull, &kEntryFull, &kModify, &kAdd, &kModDn, &kCompare, &kComparePw, &kCompareTrue, &kRef, &kDoneRef,
                                &kSaslSpnego, &kSaslGssapi, &kSaslPlain, &kBindRespSasl, &kBindRespProgress, &kWhoami, &kPwMod, &kInter, &kRespCtl}) {
        appflow::sweepPayload(*m, 389, 0x1d60);
        appflow::sweepPayload(*m, 3268, 0x1d61);
    }
}

TEST(Ldap, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"LDAP"});
}

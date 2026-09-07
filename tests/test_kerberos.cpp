// Kerberos 5 (RFC 4120): messages built from the ASN.1 of RFC 4120 section 5 by an independent DER encoder (Python, stdlib
// only) and cross-checked with
//   /opt/homebrew/opt/openssl@3/bin/openssl asn1parse -inform DER
// kAsReq:        appl [ 10 ] { SEQUENCE { cont [ 1 ] INTEGER :05, cont [ 2 ] INTEGER :0A, cont [ 3 ] { SEQUENCE { SEQUENCE {
//                cont [ 1 ] INTEGER :02 (PA-ENC-TIMESTAMP), cont [ 2 ] OCTET STRING }, SEQUENCE { cont [ 1 ] INTEGER :80 (128) ...
//                cont [ 4 ] { SEQUENCE { cont [ 0 ] BIT STRING, cont [ 1 ] { SEQUENCE { cont [ 0 ] INTEGER :01, cont [ 1 ] {
//                SEQUENCE { GENERALSTRING (alice) } } } }, cont [ 2 ] GENERALSTRING (CORP.COM), cont [ 3 ] { ... krbtgt, CORP.COM },
//                cont [ 5 ] GENERALIZEDTIME :20370913024805Z, cont [ 7 ] INTEGER :075BCD15, cont [ 8 ] { SEQUENCE { 12, 11, 17 } }
// kErrPreauth:   appl [ 30 ] { SEQUENCE { cont [ 0 ] INTEGER :05, cont [ 1 ] INTEGER :1E, cont [ 4 ] GENERALIZEDTIME
//                :20260101000000Z, cont [ 5 ] INTEGER :7B, cont [ 6 ] INTEGER :19 (error-code 25), cont [ 9 ] GENERALSTRING
//                (CORP.COM), cont [ 10 ] { krbtgt/CORP.COM }, cont [ 12 ] OCTET STRING (METHOD-DATA) }
// The old dissector took [3] of a KRB-ERROR for the realm and [9] for the error code, and pvno [1] of a KDC-REQ for the message
// type: against these messages it printed "Unknown realm=0?" and error code 20301.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/kerberos.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kAsReq = bytes("6a81a73081a4a103020105a20302010aa3243022300da103020102a206040401"
        "0203043011a10402020080a20904073005a003010100a4723070a00703050040"
        "810010a1123010a003020101a10930071b05616c696365a20a1b08434f52502e"
        "434f4da31d301ba003020102a11430121b066b72627467741b08434f52502e43"
        "4f4da511180f32303337303931333032343830355aa7060204075bcd15a80b30"
        "09020112020111020117");
    const std::string kAsReqNoPa = bytes("6a8180307ea103020105a20302010aa4723070a00703050040810010a1123010"
        "a003020101a10930071b05616c696365a20a1b08434f52502e434f4da31d301b"
        "a003020102a11430121b066b72627467741b08434f52502e434f4da511180f32"
        "303337303931333032343830355aa7060204075bcd15a80b3009020112020111"
        "020117");
    const std::string kErrPreauth = bytes("7e819130818ea003020105a10302011ea411180f323032363031303130303030"
        "30305aa50302017ba603020119a90a1b08434f52502e434f4daa1d301ba00302"
        "0102a11430121b066b72627467741b08434f52502e434f4dac3a04383036301e"
        "a103020113a21704153014a012a003020112a10b1b09434f52502e434f6d3009"
        "a103020102a20204003009a103020110a2020400");
    const std::string kErrUnknown = bytes("7e81a43081a1a003020105a10302011ea211180f323032363031303130303030"
        "30305aa303020105a411180f32303236303130313030303030315aa50502030f"
        "423fa603020107a70a1b08434f52502e434f4da810300ea003020101a1073005"
        "1b03626f62a90a1b08434f52502e434f4daa223020a003020102a11930171b04"
        "686f73741b0f6e6f737563682e636f72702e636f6dab101b0e6e6f2073756368"
        "20736572766572");
    const std::string kAsRep = bytes("6b81a63081a3a003020105a10302010ba30a1b08434f52502e434f4da4123010"
        "a003020101a10930071b05616c696365a55661543052a003020105a10a1b0843"
        "4f52502e434f4da21d301ba003020102a11430121b066b72627467741b08434f"
        "52502e434f4da320301ea003020112a103020102a2120410aaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaa61f301da003020112a2160414bbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbb");
    const std::string kTgsReq = bytes("6c783076a103020105a20302010ca30f300d300ba103020101a20404026e00a4"
        "593057a00703050040810000a20a1b08434f52502e434f4da321301fa0030201"
        "02a11830161b04636966731b0e66696c65732e636f72702e636f6da511180f32"
        "303337303931333032343830355aa70302012aa8053003020112");
    const std::string kTgsRep = bytes("6d8196308193a003020105a10302010da30a1b08434f52502e434f4da4123010"
        "a003020101a10930071b05616c696365a5526150304ea003020105a10a1b0843"
        "4f52502e434f4da221301fa003020102a11830161b04636966731b0e66696c65"
        "732e636f72702e636f6da3183016a003020117a103020101a20a0408cccccccc"
        "cccccccca6133011a003020112a20a0408dddddddddddddddd");
    const std::string kApReq = bytes("6e8183308180a003020105a10302010ea20703050020000000a3526150304ea0"
        "03020105a10a1b08434f52502e434f4da221301fa003020102a11830161b0463"
        "6966731b0e66696c65732e636f72702e636f6da3183016a003020112a1030201"
        "03a20a0408eeeeeeeeeeeeeeeea4173015a003020112a20e040cffffffffffff"
        "ffffffffffff");
    const std::string kApRep = bytes("6f233021a003020105a10302010fa2153013a003020112a20c040a1111111111"
        "1111111111");

    // KRB-SAFE / KRB-PRIV / KRB-CRED and a TGS-REQ whose padata carries an AP-REQ, an encrypted timestamp, ETYPE-INFO2 and PAC-REQUEST:
    // built by the same independent DER encoder (Python) and checked with openssl asn1parse -inform DER, e.g. kSafe:
    //   appl [ 20 ] { SEQUENCE { cont [ 0 ] INTEGER :05, cont [ 1 ] INTEGER :14, cont [ 2 ] { SEQUENCE { cont [ 0 ] OCTET STRING :hello world,
    //   cont [ 1 ] GENERALIZEDTIME :20260101000000Z, cont [ 3 ] INTEGER :4D } }, cont [ 3 ] { SEQUENCE { cont [ 0 ] INTEGER :10, cont [ 1 ] OCTET STRING } } } }
    // kTgsReq2 padata: SEQUENCE { cont [ 1 ] INTEGER :01, cont [ 2 ] OCTET STRING [HEX DUMP]:6E81... (an AP-REQ) }, { :02 ... EncryptedData },
    //   { :13 (19) ETYPE-INFO2 salt CORP.COMalice }, { :80 (128) 3005A0030101FF }
    const std::string kSafe = bytes("7450304ea003020105a103020114a2293027a00d040b68656c6c6f20776f726c"
        "64a111180f32303236303130313030303030305aa30302014da3173015a00302"
        "0110a10e040cabababababababababababab");
    const std::string kPriv = bytes("75293027a003020105a103020115a31b3019a003020112a21204102222222222"
        "2222222222222222222222");
    const std::string kCred = bytes("76753073a003020105a103020116a250304e614c304aa003020105a10a1b0843"
        "4f52502e434f4da21d301ba003020102a11430121b066b72627467741b08434f"
        "52502e434f4da3183016a003020112a103020102a20a04083333333333333333"
        "a3153013a003020100a20c040a44444444444444444444");
    const std::string kTgsReq2 = bytes("6c8201703082016ca103020105a20302010ca381ee3081eb308191a103020101"
        "a281890481866e8183308180a003020105a10302010ea20703050020000000a3"
        "526150304ea003020105a10a1b08434f52502e434f4da221301fa003020102a1"
        "1830161b04636966731b0e66696c65732e636f72702e636f6da3183016a00302"
        "0112a103020103a20a0408cccccccccccccccca4173015a003020112a20e040c"
        "ffffffffffffffffffffffff301da103020102a21604143012a003020112a20b"
        "04095555555555555555553023a103020113a21c041a30183016a003020112a1"
        "0f1b0d434f52502e434f4d616c6963653011a10402020080a20904073005a003"
        "0101ffa46f306da00703050040810000a20a1b08434f52502e434f4da321301f"
        "a003020102a11830161b04636966731b0e66696c65732e636f72702e636f6da5"
        "11180f32303337303931333032343830355aa611180f32303337303932303032"
        "343830355aa70302012aa8083006020112020111");

    std::string mark(const std::string &m) {   // RFC 4120 7.2.2: 4 byte length in front on TCP
        std::string out(4, '\0');
        out[0] = static_cast<char>(m.size() >> 24);
        out[1] = static_cast<char>(m.size() >> 16);
        out[2] = static_cast<char>(m.size() >> 8);
        out[3] = static_cast<char>(m.size());
        return out + m;
    }

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

    // one UDP datagram from a client (or the KDC) on port 88, loaded and decoded again
    packet::PacketInfo udp(const std::string &payload, bool toKdc) {
        const auto frame = toKdc ? support::udpPacket("0a000001", "0a000002", "c350", "0058", payload) : support::udpPacket("0a000002", "0a000001", "0058", "c350", payload);
        return support::parse(frame);
    }
}

TEST(Kerberos, AsReqFollowsTheKdcReqTags) {
    const auto p = udp(kAsReq, true);
    EXPECT_EQ(p.protocol, "Kerberos");
    EXPECT_EQ(p.app_type, 10u);
    EXPECT_EQ(p.info, "AS-REQ cname=alice sname=krbtgt/CORP.COM realm=CORP.COM padata=PA-ENC-TIMESTAMP,PA-PAC-REQUEST");
    EXPECT_TRUE(matches("kerberos && kerberos.msg_type == 10 && kerberos.realm == \"CORP.COM\" && kerberos.cname == \"alice\" && kerberos.sname == \"krbtgt/CORP.COM\"", p));
    EXPECT_FALSE(matches("kerberos.error_code == 0", p)) << "only a KRB-ERROR has an error code";
    EXPECT_EQ(p.info.find("Unknown"), std::string::npos);
}

TEST(Kerberos, AsReqWithoutPadata) {
    const auto p = udp(kAsReqNoPa, true);
    EXPECT_EQ(p.info, "AS-REQ cname=alice sname=krbtgt/CORP.COM realm=CORP.COM");
}

TEST(Kerberos, KrbErrorPreauthRequiredCarriesTheErrorCodeAndTheMethodData) {
    const auto p = udp(kErrPreauth, false);
    EXPECT_EQ(p.app_type, 30u);
    EXPECT_EQ(p.app_code, 25u);
    EXPECT_EQ(p.info, "KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25) sname=krbtgt/CORP.COM realm=CORP.COM padata=PA-ETYPE-INFO2,PA-ENC-TIMESTAMP,PA-PK-AS-REQ");
    EXPECT_TRUE(matches("kerberos.msg_type == 30 && kerberos.error_code == 25 && kerberos.realm == \"CORP.COM\"", p));
}

TEST(Kerberos, KrbErrorWithClientAndText) {
    const auto p = udp(kErrUnknown, false);
    EXPECT_EQ(p.app_code, 7u);
    EXPECT_EQ(p.info, "KRB-ERROR KDC_ERR_S_PRINCIPAL_UNKNOWN (7) cname=bob sname=host/nosuch.corp.com realm=CORP.COM");
    EXPECT_TRUE(matches("kerberos.cname == \"bob\" && kerberos.error_code == 7", p));
}

TEST(Kerberos, RepliesRequestsAndApMessages) {
    EXPECT_EQ(udp(kAsRep, false).info, "AS-REP cname=alice realm=CORP.COM");
    EXPECT_EQ(udp(kTgsReq, true).info, "TGS-REQ sname=cifs/files.corp.com realm=CORP.COM padata=PA-TGS-REQ");
    EXPECT_EQ(udp(kTgsRep, false).info, "TGS-REP cname=alice realm=CORP.COM");
    EXPECT_EQ(udp(kApReq, true).info, "AP-REQ sname=cifs/files.corp.com realm=CORP.COM");
    EXPECT_EQ(udp(kApRep, false).info, "AP-REP");
    EXPECT_TRUE(matches("kerberos.msg_type == 12 && kerberos.sname == \"cifs/files.corp.com\"", udp(kTgsReq, true)));
    EXPECT_FALSE(matches("kerberos.sname == \"cifs/files.corp.com\"", udp(kAsRep, false)));
}

TEST(Kerberos, TheTreeNamesEveryPartOfTheMessage) {
    Flow flow(50000, 88, "krb_tree");
    flow.client(mark(kAsReq)).server(mark(kErrPreauth)).client(mark(kAsRep));
    flow.load();
    const auto req = flow.details(0);
    EXPECT_NE(find(req.fields, "Kerberos (AS-REQ)"), nullptr);
    EXPECT_NE(find(req.fields, "pvno: 5"), nullptr);
    EXPECT_NE(find(req.fields, "msg-type: AS-REQ (10)"), nullptr);
    EXPECT_NE(find(req.fields, "PA-DATA PA-ENC-TIMESTAMP (2)"), nullptr);
    EXPECT_NE(find(req.fields, "PA-DATA PA-PAC-REQUEST (128)"), nullptr);
    EXPECT_NE(find(req.fields, "cname: alice"), nullptr);
    EXPECT_NE(find(req.fields, "name-type: NT-SRV-INST (2)"), nullptr);
    EXPECT_NE(find(req.fields, "realm: CORP.COM"), nullptr);
    EXPECT_NE(find(req.fields, "sname: krbtgt/CORP.COM"), nullptr);
    EXPECT_NE(find(req.fields, "till: 20370913024805Z"), nullptr);
    EXPECT_NE(find(req.fields, "nonce: 123456789"), nullptr);
    EXPECT_NE(find(req.fields, "ENCTYPE: aes256-cts-hmac-sha1-96 (18)"), nullptr);
    EXPECT_NE(find(req.fields, "ENCTYPE: rc4-hmac (23)"), nullptr);
    const auto err = flow.details(1);
    EXPECT_NE(find(err.fields, "error-code: KDC_ERR_PREAUTH_REQUIRED (25)"), nullptr);
    EXPECT_NE(find(err.fields, "stime: 20260101000000Z"), nullptr);
    EXPECT_NE(find(err.fields, "susec: 123"), nullptr);
    EXPECT_NE(find(err.fields, "PA-DATA PA-ETYPE-INFO2 (19)"), nullptr);
    const auto rep = flow.details(2);
    EXPECT_NE(find(rep.fields, "crealm: CORP.COM"), nullptr);
    EXPECT_NE(find(rep.fields, "ticket"), nullptr);
    EXPECT_NE(find(rep.fields, "etype: aes256-cts-hmac-sha1-96 (18)"), nullptr);
    EXPECT_NE(find(rep.fields, "kvno: 2"), nullptr);
}

TEST(Kerberos, OverTcpWithTheRecordMarkEvenSplitAndPipelined) {
    Flow flow(50000, 88, "krb_tcp");
    const std::string a = mark(kAsReq), b = mark(kErrPreauth);
    flow.client(a.substr(0, 2)).client(a.substr(2, 50)).client(a.substr(52)).server(b + mark(kApRep));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_EQ(k[2].protocol, "Kerberos");
    EXPECT_EQ(k[2].info.rfind("AS-REQ cname=alice", 0), 0u) << k[2].info;
    EXPECT_EQ(k[3].protocol, "Kerberos");
    EXPECT_NE(k[3].info.find("KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25)"), std::string::npos) << k[3].info;
    EXPECT_NE(k[3].info.find(", AP-REP"), std::string::npos) << k[3].info;
    EXPECT_TRUE(matches("kerberos.msg_type == 30", k[3]));
    flow.expectReplayEqualsLoad();
}

TEST(KerberosFramer, MarksTheLengthAndRejectsWhatIsNotKerberos) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameKerberos(s.data(), s.size()); };
    const std::string a = mark(kAsReq);
    EXPECT_EQ(frame(a.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(a.substr(0, 30)).kind, K::NeedMore);
    EXPECT_EQ(frame(a.substr(0, 30)).length, a.size());
    EXPECT_EQ(frame(a).kind, K::Complete);
    EXPECT_EQ(frame(a + a).length, a.size());
    EXPECT_EQ(frame(bytes("00000000")).kind, K::Reject) << "an empty message";
    EXPECT_EQ(frame(bytes("7fffffff6a")).kind, K::Reject) << "bigger than the stream table buffers";
    EXPECT_EQ(frame(bytes("0000000a" "300102030405060708")).kind, K::Reject) << "not an APPLICATION element";
    EXPECT_EQ(frame(bytes("1603010004" "01000000")).kind, K::Reject) << "a TLS record";
}

TEST(Kerberos, ATruncatedOrMutatedMessageStaysInsideTheFrame) {
    for (const std::string *m: {&kAsReq, &kErrPreauth, &kErrUnknown, &kAsRep, &kTgsReq, &kTgsRep, &kApReq, &kApRep}) {
        {
            const auto frame = support::udpPacket("0a000001", "0a000002", "c350", "0058", *m);
            framesweep::sweep(framesweep::Bytes(frame.begin(), frame.end()), 0x4b52);
        }
        appflow::sweepPayload(mark(*m), 88, 0x4b53);
    }
}

TEST(Kerberos, ADatagramCutShortIsMalformedButAStreamSegmentIsNot) {
    const auto cutUdp = udp(kAsReq.substr(0, 60), true);
    EXPECT_TRUE(matches("malformed", cutUdp));
    Flow flow(50000, 88, "krb_cut");
    const std::string a = mark(kAsReq);
    flow.client(a.substr(0, 60)).client(a.substr(60));
    flow.load();
    EXPECT_FALSE(matches("malformed", flow.packets()[0]));
}

TEST(Kerberos, KrbSafePrivAndCredAreLabelledAndTheirCiphersAreMarkedEncrypted) {
    const auto safe = udp(kSafe, true);
    EXPECT_EQ(safe.info, "KRB-SAFE");
    EXPECT_EQ(safe.app_type, 20u);
    EXPECT_TRUE(matches("kerberos.msg_type == 20", safe));
    EXPECT_EQ(udp(kPriv, true).info, "KRB-PRIV");
    EXPECT_EQ(udp(kCred, true).info, "KRB-CRED");
    EXPECT_TRUE(matches("kerberos.msg_type == 21", udp(kPriv, true)));
    EXPECT_TRUE(matches("kerberos.msg_type == 22", udp(kCred, true)));

    Flow flow(50000, 88, "krb_safe_priv_cred");
    flow.client(mark(kSafe)).client(mark(kPriv)).client(mark(kCred));
    flow.load();
    const auto s = flow.details(0);
    EXPECT_NE(find(s.fields, "Kerberos (KRB-SAFE)"), nullptr);
    EXPECT_NE(find(s.fields, "user-data: 11 bytes (integrity protected, not encrypted)"), nullptr);
    EXPECT_NE(find(s.fields, "timestamp: 20260101000000Z"), nullptr);
    EXPECT_NE(find(s.fields, "seq-number: 77"), nullptr);
    EXPECT_NE(find(s.fields, "cksumtype: hmac-sha1-96-aes256 (16)"), nullptr);
    const auto pr = flow.details(1);
    EXPECT_NE(find(pr.fields, "Kerberos (KRB-PRIV)"), nullptr);
    EXPECT_NE(find(pr.fields, "enc-part"), nullptr);
    EXPECT_NE(find(pr.fields, "etype: aes256-cts-hmac-sha1-96 (18)"), nullptr);
    EXPECT_NE(find(pr.fields, "cipher: 16 bytes (encrypted)"), nullptr);
    const auto cr = flow.details(2);
    EXPECT_NE(find(cr.fields, "Kerberos (KRB-CRED)"), nullptr);
    EXPECT_NE(find(cr.fields, "tickets"), nullptr);
    EXPECT_NE(find(cr.fields, "sname: krbtgt/CORP.COM"), nullptr);
    EXPECT_NE(find(cr.fields, "cipher: 8 bytes (encrypted)"), nullptr);
    EXPECT_NE(find(cr.fields, "etype: unknown (0)"), nullptr) << "the cred's own enc-part uses etype 0 (null)";
    flow.expectReplayEqualsLoad();
}

TEST(Kerberos, EveryChecksumTypeIsNamedAsInTheIanaRegistry) {
    // kSafe with the cksumtype replaced; the INTEGER is re-encoded in the shortest two's complement form and the lengths follow it
    auto safeWith = [](int type) {
        std::string v;
        if (type >= -128 && type <= 127) v = std::string(1, static_cast<char>(type));
        else v = std::string{static_cast<char>((type >> 8) & 0xff), static_cast<char>(type & 0xff)};
        const size_t extra = v.size() - 1;
        std::string m = kSafe;
        // outer APPLICATION 20 length (0x50), SEQUENCE (0x4e), [3] (0x17), SEQUENCE (0x15), [0] (0x03) and the INTEGER (0x01) grow by extra
        const std::string tail = m.substr(m.size() - 25);   // a3 17 30 15 a0 03 02 01 10 a1 0e 04 0c + 12 bytes of checksum
        std::string t = std::string{static_cast<char>(0xa3), static_cast<char>(0x17 + extra), 0x30, static_cast<char>(0x15 + extra), static_cast<char>(0xa0), static_cast<char>(3 + extra), 0x02, static_cast<char>(1 + extra)} + v + tail.substr(9);
        m = m.substr(0, m.size() - 25) + t;
        m[1] = static_cast<char>(m[1] + extra);
        m[3] = static_cast<char>(m[3] + extra);
        return m;
    };
    const std::pair<int, const char *> expected[] = {
        {1, "CRC32"}, {2, "rsa-md4"}, {3, "rsa-md4-des"}, {4, "des-mac"}, {5, "des-mac-k"}, {6, "rsa-md4-des-k"}, {7, "rsa-md5"}, {8, "rsa-md5-des"},
        {9, "rsa-md5-des3"}, {10, "sha1"}, {12, "hmac-sha1-des3-kd"}, {13, "hmac-sha1-des3"}, {14, "sha1"}, {15, "hmac-sha1-96-aes128"},
        {16, "hmac-sha1-96-aes256"}, {17, "cmac-camellia128"}, {18, "cmac-camellia256"}, {19, "hmac-sha256-128-aes128"},
        {20, "hmac-sha384-192-aes256"}, {-138, "hmac-md5"}, {11, "unknown"}, {99, "unknown"}};
    for (const auto &[type, name]: expected) {
        const std::string want = std::string("cksumtype: ") + name + " (" + std::to_string(type) + ")";
        Flow flow(50000, 88, "krb_cksum_" + std::to_string(type + 1000));
        flow.client(mark(safeWith(type)));
        flow.load();
        EXPECT_NE(find(flow.details(0).fields, want), nullptr) << want;
    }
}

TEST(Kerberos, EncryptedDataOfTicketsAndAuthenticatorsIsLabelledEncrypted) {
    Flow flow(50000, 88, "krb_encrypted");
    flow.client(mark(kApReq)).server(mark(kApRep)).server(mark(kAsRep));
    flow.load();
    const auto req = flow.details(0);
    EXPECT_NE(find(req.fields, "ap-options: 0x20000000 (mutual-required)"), nullptr);
    EXPECT_NE(find(req.fields, "authenticator"), nullptr);
    EXPECT_NE(find(req.fields, "cipher: 12 bytes (encrypted)"), nullptr);
    EXPECT_NE(find(req.fields, "cipher: 8 bytes (encrypted)"), nullptr) << "the ticket's enc-part";
    EXPECT_NE(find(req.fields, "kvno: 3"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "cipher: 10 bytes (encrypted)"), nullptr);
    EXPECT_NE(find(flow.details(2).fields, "cipher: 16 bytes (encrypted)"), nullptr);
}

TEST(Kerberos, PaDataValuesAreDecodedFurtherAndKdcOptionsAreNamed) {
    const auto p = udp(kTgsReq2, true);
    EXPECT_EQ(p.info, "TGS-REQ sname=cifs/files.corp.com realm=CORP.COM padata=PA-TGS-REQ,PA-ENC-TIMESTAMP,PA-ETYPE-INFO2,PA-PAC-REQUEST");
    Flow flow(50000, 88, "krb_padata");
    flow.client(mark(kTgsReq2));
    flow.load();
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Kerberos (AP-REQ)"), nullptr) << "PA-TGS-REQ carries an AP-REQ";
    EXPECT_NE(find(d.fields, "ap-options: 0x20000000 (mutual-required)"), nullptr);
    EXPECT_NE(find(d.fields, "PA-ENC-TS-ENC"), nullptr);
    EXPECT_NE(find(d.fields, "cipher: 9 bytes (encrypted)"), nullptr);
    EXPECT_NE(find(d.fields, "ETYPE-INFO2: aes256-cts-hmac-sha1-96 (18) salt=CORP.COMalice"), nullptr);
    EXPECT_NE(find(d.fields, "include-pac: true"), nullptr);
    EXPECT_NE(find(d.fields, "kdc-options: 0x40810000 (forwardable, renewable, canonicalize)"), nullptr);
    EXPECT_NE(find(d.fields, "rtime: 20370920024805Z"), nullptr);
    EXPECT_NE(find(d.fields, "ENCTYPE: aes128-cts-hmac-sha1-96 (17)"), nullptr);
}

TEST(Kerberos, NewMessagesStayInsideTheFrameWhenCutOrMutated) {
    for (const std::string *m: {&kSafe, &kPriv, &kCred, &kTgsReq2}) {
        const auto frame = support::udpPacket("0a000001", "0a000002", "c350", "0058", *m);
        framesweep::sweep(framesweep::Bytes(frame.begin(), frame.end()), 0x4b61);
        appflow::sweepPayload(mark(*m), 88, 0x4b62);
    }
}

TEST(Kerberos, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"Kerberos"});
}

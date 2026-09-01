// GSS-API / SPNEGO security blobs (RFC 4178, RFC 4121) and the Kerberos messages inside them, the decoder SMB2 reuses.
// Every blob is built by an independent DER encoder (Python, stdlib only) and cross-checked with
//   /opt/homebrew/opt/openssl@3/bin/openssl asn1parse -inform DER
// kInit:       0:d=0 appl [ 0 ] / OBJECT :1.3.6.1.5.5.2 / cont [ 0 ] { SEQUENCE { cont [ 0 ] { SEQUENCE { OBJECT :1.2.840.48018.1.2.2,
//              OBJECT :1.2.840.113554.1.2.2, OBJECT :1.3.6.1.4.1.311.2.2.10 } }, cont [ 2 ] { OCTET STRING [HEX DUMP]:60819306092A8648 ... } } }
//              (the mechToken is a GSS-API Kerberos token: appl [ 0 ] OBJECT :1.2.840.113554.1.2.2, then 01 00 and the AP-REQ 6E81...)
// kRespDone:   cont [ 1 ] { SEQUENCE { cont [ 0 ] ENUMERATED :00, cont [ 1 ] OBJECT :1.2.840.113554.1.2.2, cont [ 2 ] OCTET STRING (GSS AP-REP) } }
// kRespInc:    cont [ 1 ] { SEQUENCE { cont [ 0 ] ENUMERATED :01, cont [ 1 ] OBJECT :1.3.6.1.4.1.311.2.2.10, cont [ 2 ] OCTET STRING (NTLMSSP type 2) } }
// kRespRej:    cont [ 1 ] { SEQUENCE { cont [ 0 ] ENUMERATED :02 } }
// RFC 4121 4.1: after the mech OID of a Kerberos token come the two TOK_ID bytes (01 00 AP-REQ, 02 00 AP-REP, 03 00 KRB-ERROR).
#include <gtest/gtest.h>

#include <functional>
#include <string>

#include <core.h>
#include <dissect/registry.h>
#include <dissect/spnego.h>
#include <network/tcp_connection.h>

#include "app_flow.h"

using appflow::bytes;
using namespace dissect;

namespace {
    const std::string kGssApreq = bytes("60819306092a864886f71201020201006e8183308180a003020105a10302010e"
        "a20703050020000000a3526150304ea003020105a10a1b08434f52502e434f4d"
        "a221301fa003020102a11830161b04636966731b0e66696c65732e636f72702e"
        "636f6da3183016a003020112a103020103a20a0408cccccccccccccccca41730"
        "15a003020112a20e040cffffffffffffffffffffffff");
    const std::string kGssAprep = bytes("603206092a864886f71201020202006f233021a003020105a10302010fa21530"
        "13a003020112a20c040a11111111111111111111");
    const std::string kGssErr = bytes("606706092a864886f71201020203007e583056a003020105a10302011ea41118"
        "0f32303236303130313030303030305aa503020101a603020125a90a1b08434f"
        "52502e434f4daa21301fa003020102a11830161b04636966731b0e66696c6573"
        "2e636f72702e636f6d");
    const std::string kInit = bytes("6081d006062b0601050502a081c53081c2a024302206092a864882f712010202"
        "06092a864886f712010202060a2b06010401823702020aa28199048196608193"
        "06092a864886f71201020201006e8183308180a003020105a10302010ea20703"
        "050020000000a3526150304ea003020105a10a1b08434f52502e434f4da22130"
        "1fa003020102a11830161b04636966731b0e66696c65732e636f72702e636f6d"
        "a3183016a003020112a103020103a20a0408cccccccccccccccca4173015a003"
        "020112a20e040cffffffffffffffffffffffff");
    const std::string kRespDone = bytes("a14c304aa0030a0100a10b06092a864886f712010202a2360434603206092a86"
        "4886f71201020202006f233021a003020105a10302010fa2153013a003020112"
        "a20c040a11111111111111111111");
    const std::string kRespInc = bytes("a1393037a0030a0101a10c060a2b06010401823702020aa22204204e544c4d53"
        "535000020000000000000000000000000000000000000000000000");
    const std::string kRespRej = bytes("a1073005a0030a0102");
    const std::string kInitNtlm = bytes("604006062b0601050502a0363034a00e300c060a2b06010401823702020aa222"
        "04204e544c4d5353500001000000000000000000000000000000000000000000"
        "0000");
    const std::string kApreq = bytes("6e8183308180a003020105a10302010ea20703050020000000a3526150304ea0"
        "03020105a10a1b08434f52502e434f4da221301fa003020102a11830161b0463"
        "6966731b0e66696c65732e636f72702e636f6da3183016a003020112a1030201"
        "03a20a0408cccccccccccccccca4173015a003020112a20e040cffffffffffff"
        "ffffffffffff");
    const std::string kKrberr = bytes("7e583056a003020105a10302011ea411180f3230323630313031303030303030"
        "5aa503020101a603020125a90a1b08434f52502e434f4daa21301fa003020102"
        "a11830161b04636966731b0e66696c65732e636f72702e636f6d");

    struct Decoded {
        std::string data;
        SecurityBlob blob;
        packet::Field root;
    };

    Decoded decode(const std::string &data, dissect::ParseMode mode = dissect::ParseMode::Full) {
        Decoded d;
        d.data = data;
        packet::PacketInfo pack;
        network::TCPConnection tcp;
        Context ctx(pack, d.data.data(), d.data.size(), tcp, Registry::builtin(), mode);
        d.root = packet::Field{"blob", 0, static_cast<uint32_t>(d.data.size()), {}};
        d.blob = decodeSecurityBlob(ctx, reinterpret_cast<const uint8_t *>(d.data.data()), d.data.size(), &d.root);
        return d;
    }

    const packet::Field *find(const packet::Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) if (auto *r = find(c, prefix)) return r;
        return nullptr;
    }

    void expectInside(const packet::Field &f, size_t frame, const std::string &what) {
        EXPECT_LE(static_cast<size_t>(f.offset) + f.length, frame) << what << ": " << f.text;
        for (const auto &c: f.children) expectInside(c, frame, what);
    }

    // DER by hand for the nesting test: [APPLICATION 0] { SPNEGO, [0] { SEQUENCE { [2] { OCTET STRING token } } } }
    std::string len(size_t n) {
        if (n < 128) return std::string(1, static_cast<char>(n));
        return std::string(1, '\x82') + static_cast<char>(n >> 8) + static_cast<char>(n & 0xff);
    }
    std::string tlv(char tag, const std::string &c) { return std::string(1, tag) + len(c.size()) + c; }
    std::string wrapInit(const std::string &token) {
        return tlv(0x60, bytes("06062b0601050502") + tlv(static_cast<char>(0xa0), tlv(0x30, tlv(static_cast<char>(0xa2), tlv(0x04, token)))));
    }
}

TEST(Spnego, NegTokenInitOffersMechanismsAndCarriesAKerberosApReq) {
    const auto d = decode(kInit);
    ASSERT_TRUE(d.blob.ok);
    EXPECT_EQ(d.blob.kind, "SPNEGO NegTokenInit");
    ASSERT_EQ(d.blob.offeredMechs.size(), 3u);
    EXPECT_EQ(d.blob.offeredMechs[0], "1.2.840.48018.1.2.2");
    EXPECT_EQ(d.blob.offeredMechs[1], "1.2.840.113554.1.2.2");
    EXPECT_EQ(d.blob.offeredMechs[2], "1.3.6.1.4.1.311.2.2.10");
    EXPECT_TRUE(d.blob.hasKerberos);
    EXPECT_EQ(d.blob.kerberos.typeName, "AP-REQ");
    EXPECT_EQ(d.blob.kerberos.appTag, 14u);
    EXPECT_EQ(d.blob.kerberos.sname, "cifs/files.corp.com");
    EXPECT_EQ(d.blob.kerberos.realm, "CORP.COM");
    EXPECT_NE(d.blob.mechToken, nullptr);
    EXPECT_EQ(d.blob.mechTokenLength, kGssApreq.size());
    EXPECT_EQ(d.blob.summary, "SPNEGO NegTokenInit [Kerberos 5 (MS), Kerberos 5, NTLMSSP] > AP-REQ sname=cifs/files.corp.com realm=CORP.COM");
    EXPECT_FALSE(d.blob.hasNtlmssp);
    // the tree
    EXPECT_NE(find(d.root, "GSS-API Generic Security Service Application Program Interface"), nullptr);
    EXPECT_NE(find(d.root, "OID: 1.3.6.1.5.5.2 (SPNEGO)"), nullptr);
    EXPECT_NE(find(d.root, "Simple Protected Negotiation: negTokenInit"), nullptr);
    EXPECT_NE(find(d.root, "mechTypes (3): Kerberos 5 (MS), Kerberos 5, NTLMSSP"), nullptr);
    EXPECT_NE(find(d.root, "1.2.840.113554.1.2.2 (Kerberos 5)"), nullptr);
    EXPECT_NE(find(d.root, "mechToken (" + std::to_string(kGssApreq.size()) + " bytes)"), nullptr);
    EXPECT_NE(find(d.root, "krb5_tok_id: AP-REQ (0x0100)"), nullptr);
    EXPECT_NE(find(d.root, "Kerberos (AP-REQ)"), nullptr);
    EXPECT_NE(find(d.root, "ap-options: 0x20000000 (mutual-required)"), nullptr);
    EXPECT_NE(find(d.root, "cipher: 12 bytes (encrypted)"), nullptr);
    expectInside(d.root, d.data.size(), "init");
}

TEST(Spnego, NegTokenRespCarriesTheStateTheMechanismAndAKerberosApRep) {
    const auto d = decode(kRespDone);
    ASSERT_TRUE(d.blob.ok);
    EXPECT_EQ(d.blob.kind, "SPNEGO NegTokenResp");
    EXPECT_EQ(d.blob.negState, "accept-completed");
    EXPECT_EQ(d.blob.mech, "1.2.840.113554.1.2.2");
    EXPECT_TRUE(d.blob.hasKerberos);
    EXPECT_EQ(d.blob.kerberos.typeName, "AP-REP");
    EXPECT_EQ(d.blob.summary, "SPNEGO NegTokenResp accept-completed > AP-REP");
    EXPECT_NE(find(d.root, "negState: accept-completed (0)"), nullptr);
    EXPECT_NE(find(d.root, "supportedMech: 1.2.840.113554.1.2.2 (Kerberos 5)"), nullptr);
    EXPECT_NE(find(d.root, "responseToken ("), nullptr);
    expectInside(d.root, d.data.size(), "resp");
}

TEST(Spnego, NtlmsspIsLocatedButLeftToTheProtocolThatCarriesIt) {
    const auto inc = decode(kRespInc);
    ASSERT_TRUE(inc.blob.ok);
    EXPECT_EQ(inc.blob.negState, "accept-incomplete");
    EXPECT_EQ(inc.blob.mech, "1.3.6.1.4.1.311.2.2.10");
    EXPECT_TRUE(inc.blob.hasNtlmssp);
    EXPECT_FALSE(inc.blob.hasKerberos);
    ASSERT_NE(inc.blob.ntlmssp, nullptr);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(inc.blob.ntlmssp), 8), std::string("NTLMSSP\0", 8));
    EXPECT_EQ(inc.blob.ntlmsspLength, 32u) << "the NTLMSSP message: signature, type, 20 filler bytes";
    EXPECT_EQ(inc.blob.summary, "SPNEGO NegTokenResp accept-incomplete > NTLMSSP_CHALLENGE");
    const auto ini = decode(kInitNtlm);
    EXPECT_EQ(ini.blob.summary, "SPNEGO NegTokenInit [NTLMSSP] > NTLMSSP_NEGOTIATE");
    EXPECT_TRUE(ini.blob.hasNtlmssp);
    const auto raw = decode(bytes("4e544c4d535350000300000000"));
    EXPECT_EQ(raw.blob.kind, "NTLMSSP_AUTH");
}

TEST(Spnego, ARejectionHasNoToken) {
    const auto d = decode(kRespRej);
    ASSERT_TRUE(d.blob.ok);
    EXPECT_EQ(d.blob.negState, "reject");
    EXPECT_EQ(d.blob.mechToken, nullptr);
    EXPECT_FALSE(d.blob.hasKerberos);
    EXPECT_EQ(d.blob.summary, "SPNEGO NegTokenResp reject");
}

TEST(Spnego, BareGssApiKerberosTokensAndBareKerberosMessages) {
    const auto req = decode(kGssApreq);
    ASSERT_TRUE(req.blob.ok);
    EXPECT_EQ(req.blob.kind, "GSS-API Kerberos 5 AP-REQ");
    EXPECT_EQ(req.blob.mech, "1.2.840.113554.1.2.2");
    EXPECT_EQ(req.blob.kerberos.sname, "cifs/files.corp.com");
    EXPECT_EQ(decode(kGssAprep).blob.kind, "GSS-API Kerberos 5 AP-REP");
    const auto err = decode(kGssErr);
    EXPECT_EQ(err.blob.kind, "GSS-API Kerberos 5 KRB-ERROR");
    EXPECT_EQ(err.blob.kerberos.errorCode, 37);
    EXPECT_EQ(err.blob.summary, "KRB-ERROR KRB_AP_ERR_SKEW (37) sname=cifs/files.corp.com realm=CORP.COM");
    EXPECT_NE(find(err.root, "error-code: KRB_AP_ERR_SKEW (37)"), nullptr);
    const auto rawReq = decode(kApreq);
    ASSERT_TRUE(rawReq.blob.ok);
    EXPECT_TRUE(rawReq.blob.hasKerberos);
    EXPECT_EQ(rawReq.blob.kind, "Kerberos AP-REQ");
    EXPECT_EQ(decode(kKrberr).blob.kerberos.errorCode, 37);
    expectInside(req.root, req.data.size(), "gss");
    expectInside(err.root, err.data.size(), "gss err");
}

TEST(Spnego, WrapAndMicTokensAreLabelledNotDecoded) {
    const auto wrap = decode(bytes("050401ff000c000000000000aabbccdd"));
    EXPECT_TRUE(wrap.blob.ok);
    EXPECT_EQ(wrap.blob.kind, "GSS-API Kerberos Wrap token");
    EXPECT_EQ(decode(bytes("040401ff")).blob.kind, "GSS-API Kerberos MIC token");
}

TEST(Spnego, WhatIsNotASecurityBlobIsNotRecognised) {
    EXPECT_FALSE(decode("").blob.ok);
    EXPECT_FALSE(decode(bytes("00")).blob.ok);
    EXPECT_FALSE(decode(bytes("1603010004" "01000000")).blob.ok);
    EXPECT_FALSE(decode(bytes("3003020101")).blob.ok);
    EXPECT_FALSE(decode(bytes("6000")).blob.ok) << "an empty GSS-API token has no mechanism";
    EXPECT_FALSE(decode(bytes("a000")).blob.ok);
}

TEST(Spnego, TheSummaryPassBuildsNoTree) {
    const auto d = decode(kInit, dissect::ParseMode::Summary);
    ASSERT_TRUE(d.blob.ok);
    EXPECT_TRUE(d.root.children.empty());
    EXPECT_EQ(d.blob.kerberos.sname, "cifs/files.corp.com");
}

TEST(Spnego, NestingOfTokensInsideTokensIsBounded) {
    std::string token = kGssApreq;
    for (int i = 0; i < 8; ++i) token = wrapInit(token);
    const auto d = decode(token);
    ASSERT_TRUE(d.blob.ok);
    EXPECT_EQ(d.blob.kind, "SPNEGO NegTokenInit");
    EXPECT_FALSE(d.blob.hasKerberos) << "the Kerberos token is eight tokens deep, beyond the bound";
    expectInside(d.root, d.data.size(), "nested");
    const auto shallow = decode(wrapInit(kGssApreq));
    EXPECT_TRUE(shallow.blob.hasKerberos);
}

TEST(Spnego, ACutOrMutatedBlobStaysInsideTheBytesItWasGiven) {
    for (const std::string *m: {&kInit, &kRespDone, &kRespInc, &kRespRej, &kInitNtlm, &kGssApreq, &kGssAprep, &kGssErr, &kApreq}) {
        for (size_t cut = 0; cut <= m->size(); ++cut) {
            const auto d = decode(m->substr(0, cut));
            expectInside(d.root, cut, "cut " + std::to_string(cut));
        }
        uint32_t seed = 0x5eed1234;
        for (int n = 0; n < 1500; ++n) {
            std::string x = *m;
            for (int k = 0; k < 1 + n % 3; ++k) {
                seed = seed * 1664525u + 1013904223u;
                x[(seed >> 8) % x.size()] = static_cast<char>(seed >> 24);
            }
            if (n % 5 == 0) x.resize(x.size() - (seed >> 4) % x.size());
            const auto d = decode(x);
            expectInside(d.root, x.size(), "mutated " + std::to_string(n));
        }
    }
}

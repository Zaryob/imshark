// SMB2 Session Setup with a SPNEGO security blob (NTLMSSP inside, Kerberos inside) and the SMB1 negotiate that leads to SMB2.
// Oracle: an independent Python encoder (scratchpad secvec.py): DER for SPNEGO (RFC 4178) with the OIDs 1.3.6.1.5.5.2 and
// 1.3.6.1.4.1.311.2.2.10 written as bytes, the NTLMSSP messages from the [MS-NLMP] 2.2.1.1-2.2.1.3 layouts (Len, MaxLen, Offset
// fields; AV_PAIR ids of 2.2.2.1), the SMB1 header of [MS-CIFS] 2.2.3.1 and the Negotiate dialect strings of 2.2.4.52. The Kerberos
// vectors are the DER AP-REQ / AP-REP of test_spnego.cpp (checked there with OpenSSL asn1parse) wrapped in Session Setup.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // clang-format off
const std::string kSsNegInit = bytes("000000a2fe534d42400001000000000001000100000000000000000001000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000190000017f0000000000000058004a00000000000000000060480606"
        "2b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e54"
        "4c4d5353500001000000978208e2000000000000000000000000000000000a00"
        "614a0000000f");
const std::string kSsChallenge = bytes("0000011dfe534d4240000100160000c001000100010000000000000001000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "00000000090000004800d500a181d23081cfa0030a0101a10c060a2b06010401"
        "823702020aa281b90481b64e544c4d5353500002000000080008003800000097"
        "8a89e20123456789abcdef000000000000000076007600400000000a00634500"
        "00000f43004f00520050000200080043004f005200500001000e00460049004c"
        "0045005300300031000400180063006f00720070002e006500780061006d0070"
        "006c00650003002800660069006c0065007300300031002e0063006f00720070"
        "002e006500780061006d0070006c0065000700080080758aa3096fda01000000"
        "00");
const std::string kSsAuth = bytes("00000133fe534d42400001000000000001000100000000000000000002000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "00000000190000017f000000000000005800db000000000000000000a181d830"
        "81d5a0030a0101a281cd0481ca4e544c4d535350000300000018001800580000"
        "00300030007000000008000800a00000000a000a00a800000008000800b20000"
        "0010001000ba000000158288e20a00614a0000000feeeeeeeeeeeeeeeeeeeeee"
        "eeeeeeeeee000000000000000000000000000000000000000000000000000102"
        "030405060708090a0b0c0d0e0f0101000000000000aaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaa43004f005200500061006c0069006300650050"
        "0043003000310055555555555555555555555555555555");
const std::string kSsDone = bytes("00000051fe534d42400001000000000001000100010000000000000002000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "000000000900000048000900a1073005a0030a0100");
const std::string kSmb1NegReq = bytes("00000068ff534d4272000000001853c80000000000000000000000000000fffe"
        "00000100004500025043204e4554574f524b2050524f4752414d20312e300002"
        "4c414e4d414e312e3000024e54204c4d20302e31320002534d4220322e303032"
        "0002534d4220322e3f3f3f00");
const std::string kSmb1NegResp = bytes("00000045ff534d4272000000009853c80000000000000000000000000000fffe"
        "000001001102000332000100044100000000010078563412fce3008080758aa3"
        "096fda010000000000");
const std::string kSsKrbReq = bytes("0000012bfe534d42400001000000000001000100000000000000000003000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000190000017f000000000000005800d30000000000000000006081d006"
        "062b0601050502a081c53081c2a024302206092a864882f71201020206092a86"
        "4886f712010202060a2b06010401823702020aa2819904819660819306092a86"
        "4886f71201020201006e8183308180a003020105a10302010ea2070305002000"
        "0000a3526150304ea003020105a10a1b08434f52502e434f4da221301fa00302"
        "0102a11830161b04636966731b0e66696c65732e636f72702e636f6da3183016"
        "a003020112a103020103a20a0408cccccccccccccccca4173015a003020112a2"
        "0e040cffffffffffffffffffffffff");
const std::string kSsKrbResp = bytes("00000096fe534d42400001000000000001000100010000000000000003000000"
        "0000000000000000000000000100100000000000000000000000000000000000"
        "000000000900000048004e00a14c304aa0030a0100a10b06092a864886f71201"
        "0202a2360434603206092a864886f71201020202006f233021a003020105a103"
        "02010fa2153013a003020112a20c040a11111111111111111111");
const std::string kSsBareNtlm = bytes("00000088fe534d42400001000000000001000100000000000000000004000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000190000017f000000000000005800300000000000000000004a554e4b"
        "313233344e544c4d5353500001000000978208e2000000000000000000000000"
        "000000000a00614a0000000f");
    // clang-format on

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }
}

TEST(Smb2Security, AnNtlmRoundTripInsideSpnegoIsDecodedMessageByMessage) {
    Flow flow(50000, 445, "smb2_spnego_ntlm");
    flow.client(kSsNegInit).server(kSsChallenge).client(kSsAuth).server(kSsDone);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Session Setup Request [SPNEGO NegTokenInit [NTLMSSP] > NTLMSSP_NEGOTIATE]");
    EXPECT_EQ(k[1].info, "Session Setup Response, STATUS_MORE_PROCESSING_REQUIRED [SPNEGO NegTokenResp accept-incomplete > NTLMSSP_CHALLENGE]");
    EXPECT_EQ(k[2].info, "Session Setup Request [SPNEGO NegTokenResp accept-incomplete > NTLMSSP_AUTH] user=CORP\\alice");
    EXPECT_EQ(k[3].info, "Session Setup Response, STATUS_SUCCESS [SPNEGO NegTokenResp accept-completed]");
    EXPECT_EQ(k[2].app_text, "CORP\\alice");
    auto f = filter::Filter::compile("smb2.user == \"CORP\\\\alice\"");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(k[2]));

    const auto negotiate = flow.details(0);
    EXPECT_NE(find(negotiate.fields, "Simple Protected Negotiation: negTokenInit"), nullptr);
    EXPECT_NE(find(negotiate.fields, "mechTypes (1): NTLMSSP"), nullptr);
    EXPECT_NE(find(negotiate.fields, "NTLM Secure Service Provider"), nullptr);
    EXPECT_NE(find(negotiate.fields, "Negotiate Flags: 0xe2088297 (UNICODE, OEM, REQUEST_TARGET, SIGN, LM_KEY, NTLM, ALWAYS_SIGN, EXTENDED_SESSIONSECURITY, VERSION, 128, KEY_EXCH, 56)"), nullptr);
    EXPECT_NE(find(negotiate.fields, "Version: 10.0 (build 19041)"), nullptr);

    const auto challenge = flow.details(1);
    EXPECT_NE(find(challenge.fields, "negState: accept-incomplete (1)"), nullptr);
    EXPECT_NE(find(challenge.fields, "Target Name: CORP"), nullptr);
    EXPECT_NE(find(challenge.fields, "NTLM Server Challenge: 0123456789abcdef"), nullptr);
    EXPECT_NE(find(challenge.fields, "NetBIOS domain name: CORP"), nullptr);
    EXPECT_NE(find(challenge.fields, "NetBIOS computer name: FILES01"), nullptr);
    EXPECT_NE(find(challenge.fields, "DNS domain name: corp.example"), nullptr);
    EXPECT_NE(find(challenge.fields, "DNS computer name: files01.corp.example"), nullptr);
    EXPECT_NE(find(challenge.fields, "Timestamp: 2024-03-05 14:30:15 UTC"), nullptr);
    EXPECT_NE(find(challenge.fields, "Session Flags: 0x0000"), nullptr);

    const auto auth = flow.details(2);
    EXPECT_NE(find(auth.fields, "Domain: CORP"), nullptr);
    EXPECT_NE(find(auth.fields, "User: alice"), nullptr);
    EXPECT_NE(find(auth.fields, "Workstation: PC01"), nullptr);
    EXPECT_NE(find(auth.fields, "LM Response (24 bytes)"), nullptr);
    EXPECT_NE(find(auth.fields, "NT Response (48 bytes, NTLMv2)"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Security, KerberosInsideSpnegoShowsTheTicketServiceAndRealm) {
    Flow flow(50000, 445, "smb2_spnego_krb");
    flow.client(kSsKrbReq).server(kSsKrbResp);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Session Setup Request [SPNEGO NegTokenInit [Kerberos 5 (MS), Kerberos 5, NTLMSSP] > AP-REQ sname=cifs/files.corp.com realm=CORP.COM]");
    EXPECT_EQ(k[1].info.rfind("Session Setup Response, STATUS_SUCCESS [SPNEGO NegTokenResp accept-completed > ", 0), 0u) << k[1].info;
    const auto req = flow.details(0);
    EXPECT_NE(find(req.fields, "Security Buffer ("), nullptr);
    EXPECT_NE(find(req.fields, "krb5_tok_id: AP-REQ (0x0100)"), nullptr);
    EXPECT_NE(find(req.fields, "Kerberos (AP-REQ)"), nullptr);
    EXPECT_NE(find(req.fields, "ap-options: 0x20000000 (mutual-required)"), nullptr);
    EXPECT_NE(find(req.fields, "cipher: 12 bytes (encrypted)"), nullptr);
    EXPECT_EQ(k[0].app_text, "") << "the user of a Kerberos logon is inside the encrypted authenticator";
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Security, ASecurityBufferThatIsNotAGssTokenButHoldsNtlmsspIsStillFound) {
    Flow flow(50000, 445, "smb2_bare_ntlm");
    flow.client(kSsBareNtlm);   // eight bytes of junk in front of the NTLMSSP message
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Session Setup Request [NTLMSSP_NEGOTIATE]");
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Security, Smb1NegotiateIsRecognisedAndTheDialectsShown) {
    Flow flow(50000, 445, "smb1_negotiate");
    flow.client(kSmb1NegReq).server(kSmb1NegResp);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].protocol, "SMB");
    EXPECT_EQ(k[0].info, "SMB1 Negotiate Request [PC NETWORK PROGRAM 1.0, LANMAN1.0, NT LM 0.12, SMB 2.002, SMB 2.???]");
    EXPECT_EQ(k[1].protocol, "SMB");
    EXPECT_EQ(k[1].info, "SMB1 Negotiate Response, STATUS_SUCCESS, Dialect index 2");
    const auto req = flow.details(0);
    EXPECT_NE(find(req.fields, "Requested Dialects (5): PC NETWORK PROGRAM 1.0"), nullptr);
    EXPECT_NE(find(req.fields, "SMB 2.002 (SMB2)"), nullptr);
    EXPECT_NE(find(req.fields, "Command: Negotiate (0x72)"), nullptr);
    EXPECT_NE(find(req.fields, "Multiplex ID: 0x0001"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "Dialect Index: 2"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Smb2Security, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kSsNegInit, &kSsChallenge, &kSsAuth, &kSsDone, &kSsKrbReq, &kSsKrbResp, &kSsBareNtlm, &kSmb1NegReq, &kSmb1NegResp}) {
        appflow::sweepPayload(*m, 445, 0x5ec0);
        appflow::sweepPayload(*m, 139, 0x5ec1);
    }
}

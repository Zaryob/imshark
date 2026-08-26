// IKEv2 / IKEv1 payload contents (RFC 7296, RFC 7383, RFC 2408, RFC 2409, RFC 2407).
//
// Oracle: the messages below were built by an independent script (Python standard library only) straight from the layouts in the
// RFCs - generic payload header, proposal / transform / attribute substructures, notify, traffic selector and so on - with the
// NAT detection hashes (RFC 7296 2.23: SHA-1 over SPIs, address and port), the RFC 3947 vendor ID (MD5 of "RFC 3947") and the CA hashes
// computed by hashlib / socket. The payloads that real peers only send encrypted (ID, CERT, AUTH, TS, ...) are in plain chains here,
// the way a tool that has the keys would present them; the dissector must read them, and must NOT read what follows an SK payload or
// follows the encryption flag of IKEv1.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>

#include "frame_sweep.h"
#include "ipsec_support.h"
#include "support.h"

using namespace ipsectest;

namespace {
    const char *kM1 = "010203040506070800000000000000002120220800000000000000d7220000300000002c010100040300000c0100000c800e01000300000802000005030000080300000c000000080400000e28000018000e0000000102030405060708090a0b0c0d0e0f29000014404142434445464748494a4b4c4d4e4f2900001c00004004644b4575455bd6fcc1efe2be8162a9218e448e5f2900001c00004005ffb5f34c3c39a75de3d3bfacc231e5649f991d18290000080000402e2b0000100000402f00010002000300040000000f746573742d76656e646f72";
    const char *kM2 = "0102030405060708a1a2a3a4a5a6a7a8292022200000000000000024000000080000000e";
    const char *kM3 = "0102030405060708a1a2a3a4a5a6a7a82e202308000000010000005023000034052a4f7499bee3082d52779cc1e60b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0";
    const char *kM4 = "0102030405060708a1a2a3a4a5a6a7a83520230800000001000000440000002800020003010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56";
    const char *kM5 = "0102030405060708a1a2a3a4a5a6a7a82320230800000001000001472400001a02000000636c69656e742e6578616d706c652e6f72672500000c01000000c63364022600002304000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2700002d0459eaa5cc7467b1e19509572f6dacb838bf3957d9526ca3cef0721630ac8984d0c74fbcc0a9b6bade2c00004801000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f2d00001801000000070600100000ffff0a0000000a0000ff2a000028020000000711001000350035c0a80101c0a80101070000100000ffffac100000ac10ffff2f00001003040002c0ffee01c0ffee023000001401000000000100000003000000070000000000090107000501";
    const char *kM6 = "010203040506070800000000000000000110020000000000000000980d00005400000001000000010000004801010002030000280101000080010007800e010080020002800300018004000e800b0001000c0004000070800000001802010000800100058002000180030001800400020d0000144a131c81070358455c5728f20e95452f00000014afcad71368a1f1c96b8696fc77570100";
    const char *kM7 = "0102030405060708a1a2a3a4a5a6a7a808102001aabbccdd0000005403203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e";
    const char *kM8 = "0102030405060708a1a2a3a4a5a6a7a80110040000000000000000db0400005400000001000000010000004801010002030000280101000080010007800e010080020002800300018004000e800b0001000c0004000070800000001802010000800100058002000180030001800400020a000014000102030405060708090a0b0c0d0e0f05000014202122232425262728292a2b2c2d2e2f0d000017021101f476706e2e6578616d706c652e6f7267140000144a131c81070358455c5728f20e95452f00000018644b4575455bd6fcc1efe2be8162a9218e448e5f";
    const char *kM9 = "0102030405060708a1a2a3a4a5a6a7a808100500010203040000005c0b000018000102030405060708090a0b0c0d0e0f101112130c000014000000010304000e11223344696e666f000000140000000103040002c0ffee01c0ffee02";
    const char *kM10 = "0102030405060708a1a2a3a4a5a6a7a8081020000a0b0c0d000000ac01000018000102030405060708090a0b0c0d0e0f101112130a000044000000010000000100000038010304020badc0de03000020010c00008001000180020e1080040001800500028003000e800600800000000c020300008004000205000014000102030405060708090a0b0c0d0e0f05000010040000000a000000ffffff000000001007060050c0a80001c0a80009";

    Bytes bytesOf(const char *hex) {
        const auto raw = support::hex(hex);
        return Bytes(raw.begin(), raw.end());
    }

    Bytes ikeFrame(const char *hex, bool port4500 = false) {
        Bytes data;
        if (port4500) data = {0, 0, 0, 0};   // Non-ESP marker (RFC 3948)
        const Bytes ike = bytesOf(hex);
        data.insert(data.end(), ike.begin(), ike.end());
        const uint16_t port = port4500 ? 4500 : 500;
        return framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(port, port, data)));
    }

    Decoded ike(const char *hex) { return decode(ikeFrame(hex)); }

    void expectTree(const Decoded &d, std::initializer_list<const char *> texts) {
        for (const char *t: texts) EXPECT_TRUE(treeHas(d.p, t)) << "missing in the tree: " << t;
    }
} // namespace

TEST(IkeV2, SaInitRequestShowsProposalsKeyExchangeNonceNotifiesAndVendorId) {
    const auto d = ike(kM1);
    EXPECT_EQ(d.p.protocol, "IKEv2");
    EXPECT_NE(d.p.info.find("IKE_SA_INIT"), std::string::npos);
    EXPECT_NE(d.p.info.find(", Initiator"), std::string::npos) << d.p.info;
    EXPECT_NE(d.p.info.find("[NAT_DETECTION_SOURCE_IP]"), std::string::npos) << d.p.info;
    expectTree(d, {"Payload: Security Association (SA)", "Proposal 1: IKE, 4 transform(s)", "Protocol ID: IKE (1)",
                   "Encryption Algorithm (ENCR): ENCR_AES_CBC", "Key Length: 256 bits", "Pseudorandom Function (PRF): PRF_HMAC_SHA2_256",
                   "Integrity Algorithm (INTEG): AUTH_HMAC_SHA2_256_128", "Key Exchange Method / Diffie-Hellman Group (D-H): 2048-bit MODP Group",
                   "Last Substructure: last proposal (0)", "Last Substructure: more transforms (3)",
                   "Diffie-Hellman Group: 2048-bit MODP Group (14)", "Key Exchange Data (16 bytes)", "Nonce Data (16 bytes)",
                   "Notify Message Type: NAT_DETECTION_SOURCE_IP (16388) [status]", "Notify Message Type: NAT_DETECTION_DESTINATION_IP (16389)",
                   "SHA-1 hash of SPIs, address and port: 644b4575455bd6fcc1efe2be8162a9218e448e5f",
                   "Notify Message Type: IKEV2_FRAGMENTATION_SUPPORTED (16430)",
                   "Hash algorithms: SHA1 (1), SHA2-256 (2), SHA2-384 (3), SHA2-512 (4)", "Vendor ID: \"test-vendor\"",
                   "Critical: No", "Initiator SPI: 0x0102030405060708", "Responder SPI: 0x0000000000000000", "Initiator: Yes"});
    EXPECT_TRUE(d.matches("ike && ike.version == 2 && ike.exchange_type == 34 && ike.message_id == 0 && ike.notify.type == 16388 && !ike.fragment"));
    EXPECT_TRUE(d.matches("ike.initiator_spi == \"0x0102030405060708\" && ike.responder_spi == \"0x0000000000000000\""));
    EXPECT_FALSE(d.matches("ike.notify.type == 14"));
    framesweep::expectInside(d.p, ikeFrame(kM1).size(), "m1");
    // Summary and Full agree
    const auto s = decode(ikeFrame(kM1), false, dissect::ParseMode::Summary);
    EXPECT_EQ(s.p.protocol, d.p.protocol);
    EXPECT_EQ(s.p.info, d.p.info);
    EXPECT_EQ(s.p.app_flags, d.p.app_flags);
    EXPECT_EQ(s.p.app_text, d.p.app_text);
    // the same message after a Non-ESP marker on 4500
    const auto n = decode(ikeFrame(kM1, true));
    EXPECT_EQ(n.p.protocol, "IKEv2");
    EXPECT_TRUE(treeHas(n.p, "Proposal 1: IKE, 4 transform(s)"));
}

TEST(IkeV2, ErrorNotifyInAResponse) {
    const auto d = ike(kM2);
    EXPECT_NE(d.p.info.find(", Response"), std::string::npos) << d.p.info;
    EXPECT_NE(d.p.info.find("[NO_PROPOSAL_CHOSEN]"), std::string::npos) << d.p.info;
    EXPECT_TRUE(treeHas(d.p, "Notify Message Type: NO_PROPOSAL_CHOSEN (14) [error]"));
    EXPECT_TRUE(d.matches("ike.notify.type == 14 && ike.responder_spi == \"0xa1a2a3a4a5a6a7a8\""));
}

TEST(IkeV2, EncryptedPayloadIsLabelledAndNeverInterpreted) {
    const auto d = ike(kM3);
    EXPECT_EQ(d.p.protocol, "IKEv2");
    EXPECT_NE(d.p.info.find("IKE_AUTH"), std::string::npos);
    EXPECT_NE(d.p.info.find("(encrypted)"), std::string::npos) << d.p.info;
    expectTree(d, {"Payload: Encrypted and Authenticated (SK)", "Encrypted Data (48 bytes: IV, cipher text, padding and ICV; not interpreted)",
                   "[first inner payload, encrypted]"});
    EXPECT_FALSE(treeHas(d.p, "Payload: Identification")) << "what follows an SK payload is cipher text";
    EXPECT_FALSE(d.matches("ike.fragment"));
    EXPECT_FALSE(d.matches("ike.notify.type > 0"));
}

TEST(IkeV2, EncryptedFragmentsAreLabelledWithTheirNumbers) {
    const auto d = ike(kM4);   // RFC 7383 3: the second of three, so Next Payload is 0
    EXPECT_NE(d.p.info.find("Fragment 2/3 (encrypted)"), std::string::npos) << d.p.info;
    expectTree(d, {"Payload: Encrypted Fragment (SKF)", "Fragment Number: 2", "Total Fragments: 3", "[not the first fragment: no inner payload type]",
                   "Encrypted Data (32 bytes: IV, cipher text, padding and ICV; not interpreted)"});
    EXPECT_TRUE(d.matches("ike.fragment && ike.fragment.number == 2 && ike.fragment.total == 3"));
    EXPECT_FALSE(d.matches("ike.fragment.number == 3"));
    EXPECT_FALSE(treeHas(d.p, "Payload: Identification"));
}

TEST(IkeV2, EveryPayloadKindIsDecoded) {
    const auto d = ike(kM5);
    EXPECT_EQ(d.p.protocol, "IKEv2");
    expectTree(d, {"ID Type: ID_FQDN (2)", "Identification Data: client.example.org", "ID Type: ID_IPV4_ADDR (1)", "Identification Data: 198.51.100.2",
                   "Certificate Encoding: X.509 Certificate - Signature (4)", "Certificate Data (30 bytes)",
                   "Certification Authority: 2 SHA-1 hash(es)",
                   "SHA-1 hash of CA public key: 59eaa5cc7467b1e19509572f6dacb838bf3957d9", "SHA-1 hash of CA public key: 526ca3cef0721630ac8984d0c74fbcc0a9b6bade",
                   "Auth Method: RSA Digital Signature (1)", "Authentication Data (64 bytes)",
                   "Number of Traffic Selectors: 1", "Traffic Selector 1: 10.0.0.0 - 10.0.0.255, TCP (6), ports 0-65535",
                   "Traffic Selector 1: 192.168.1.1 - 192.168.1.1, UDP (17), ports 53-53", "Traffic Selector 2: 172.16.0.0 - 172.16.255.255, any (0), ports 0-65535",
                   "TS Type: TS_IPV4_ADDR_RANGE (7)", "Starting Address: 10.0.0.0", "Ending Address: 10.0.0.255",
                   "Protocol ID: ESP (3)", "SPI Size: 4", "Number of SPIs: 2", "SPI: c0ffee01", "SPI: c0ffee02",
                   "CFG Type: CFG_REQUEST (1)", "Attribute: INTERNAL_IP4_ADDRESS (0 bytes)", "Attribute: INTERNAL_IP4_DNS (0 bytes)", "Attribute: APPLICATION_VERSION (0 bytes)",
                   "EAP Code: Request (1)", "EAP Identifier: 7", "EAP Type: 1"});
    framesweep::expectInside(d.p, ikeFrame(kM5).size(), "m5");
}

TEST(IkeV1, MainModeSaShowsTheTransformAttributesAndVendorIds) {
    const auto d = ike(kM6);
    EXPECT_EQ(d.p.protocol, "ISAKMP");
    EXPECT_NE(d.p.info.find("Identity Protection (Main Mode)"), std::string::npos);
    expectTree(d, {"Domain of Interpretation: IPSEC (1)", "Situation: 0x00000001 (SIT_IDENTITY_ONLY)", "Proposal 1: ISAKMP, 2 transform(s)",
                   "Protocol ID: PROTO_ISAKMP (1)", "Transform 1: KEY_IKE", "Encryption-Algorithm: AES-CBC (7)", "Key-Length: 256", "Hash-Algorithm: SHA (2)",
                   "Authentication-Method: Pre-shared key (1)", "Group-Description: 2048-bit MODP Group (14)", "Life-Type: Seconds (1)", "Life-Duration: 28800",
                   "Encryption-Algorithm: 3DES-CBC (5)", "Hash-Algorithm: MD5 (1)", "Group-Description: 1024-bit MODP Group (2)",
                   "Vendor ID: RFC 3947 Negotiation of NAT-Traversal in the IKE (4a131c81070358455c5728f20e95452f)", "Vendor ID: RFC 3706 DPD (Dead Peer Detection)",
                   "Flags: 0x00", "Encryption: No"});
    EXPECT_TRUE(d.matches("ike && ike.version == 1 && ike.exchange_type == 2"));
    framesweep::expectInside(d.p, ikeFrame(kM6).size(), "m6");
}

TEST(IkeV1, TheEncryptionFlagHidesEverythingAfterTheHeader) {
    const auto d = ike(kM7);
    EXPECT_EQ(d.p.protocol, "ISAKMP");
    EXPECT_NE(d.p.info.find("Quick Mode"), std::string::npos);
    EXPECT_NE(d.p.info.find(", Encrypted"), std::string::npos) << d.p.info;
    expectTree(d, {"Encrypted Payloads (56 bytes; not interpreted)", "Encryption: Yes (the payloads are not interpreted)", "Message ID: 2864434397"});
    EXPECT_FALSE(treeHas(d.p, "Payload: Hash")) << "the first payload type of an encrypted message is not a hint to read";
    EXPECT_FALSE(d.matches("ike.notify.type > 0"));
}

TEST(IkeV1, AggressiveModeCarriesKeyExchangeNonceIdentityAndNatDiscovery) {
    const auto d = ike(kM8);
    EXPECT_NE(d.p.info.find("Aggressive Mode"), std::string::npos);
    expectTree(d, {"Payload: Key Exchange (KE)", "Key Exchange Data (16 bytes)", "Payload: Nonce (NONCE)", "Nonce Data (16 bytes)",
                   "ID Type: ID_FQDN (2)", "Protocol ID: UDP (17)", "Port: 500", "Identification Data: vpn.example.org",
                   "Payload: NAT Discovery (NAT-D)", "NAT-D Hash (20 bytes): 644b4575455bd6fcc1efe2be8162a9218e448e5f"});
}

TEST(IkeV1, InformationalNotificationAndDelete) {
    const auto d = ike(kM9);
    expectTree(d, {"Hash Data (20 bytes)", "Notify Message Type: NO-PROPOSAL-CHOSEN (14) [error]", "Protocol ID: ESP (3)", "SPI: 11223344",
                   "Notification Data (4 bytes)", "Payload: Delete (D)", "Number of SPIs: 2", "SPI: c0ffee01", "SPI: c0ffee02"});
    EXPECT_NE(d.p.info.find("[Notify 14]"), std::string::npos) << d.p.info;
    EXPECT_TRUE(d.matches("ike.notify.type == 14 && ike.message_id == 16909060"));
}

TEST(IkeV1, IpsecDoiProposalsAndIdentities) {
    const auto d = ike(kM10);
    expectTree(d, {"Proposal 1: ESP, 2 transform(s)", "Protocol ID: PROTO_IPSEC_ESP (3)", "SPI: 0badc0de", "Transform 1: ESP_AES",
                   "SA-Life-Type: Seconds (1)", "SA-Life-Duration: 3600", "Encapsulation-Mode: Tunnel (1)", "Authentication-Algorithm: HMAC-SHA (2)",
                   "Group-Description: 2048-bit MODP Group (14)", "Key-Length: 128", "Transform 2: ESP_3DES", "Encapsulation-Mode: Transport (2)",
                   "ID Type: ID_IPV4_ADDR_SUBNET (4)", "Identification Data: 10.0.0.0 / 255.255.255.0",
                   "ID Type: ID_IPV4_ADDR_RANGE (7)", "Protocol ID: TCP (6)", "Port: 80", "Identification Data: 192.168.0.1 - 192.168.0.9"});
}

TEST(IkePayloads, ProtocolHierarchyNamesTheKeyExchange) {
    std::vector<packet::PacketInfo> packets = {ike(kM1).p, ike(kM6).p};
    for (auto &p: packets) p.frame_length = 100;
    const auto root = stats::protocolHierarchy(packets, nullptr);
    const auto *node = hierarchyNode(root, "Internet Key Exchange");
    ASSERT_NE(node, nullptr);
    EXPECT_EQ(node->packets, 2u);
}

TEST(IkePayloads, DamagedPayloadsStayInsideTheFrameAndAreFlaggedWhereTheChainBreaks) {
    // a transform whose length runs past its proposal, an attribute that runs past its transform, a traffic selector length of 3
    Bytes b = bytesOf(kM1);
    b[28 + 4 + 8 + 2] = 0xff;   // the first transform's length high byte
    const auto frame = framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(500, 500, b)));
    framesweep::expectInside(decode(frame).p, frame.size(), "transform length");
    const Bytes ts = bytesOf(kM5);
    const auto sweeps = {kM1, kM2, kM3, kM4, kM5, kM6, kM7, kM8, kM9, kM10};
    uint32_t seed = 0x7296'0001u;
    for (const char *hex: sweeps) {
        framesweep::sweep(ikeFrame(hex), seed++, 600);
        framesweep::sweep(ikeFrame(hex, true), seed++, 200);
    }
}

TEST(IkePayloads, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"IKEv2", "ISAKMP"});
}

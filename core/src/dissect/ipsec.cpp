// IPsec protocol dissectors:
// AH (RFC 4302), ESP (RFC 4303), and IKEv1/IKEv2 (RFC 2408 / RFC 7296)
#include "ipsec.h"

#include <string>
#include <vector>

#include "registry.h"
#include "util.h"
#include <network/byteorder.h>

using packet::Field;

namespace {
    using namespace dissect;

    uint16_t readU16(const uint8_t *p) {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    }

    uint32_t readU32(const uint8_t *p) {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8)  |
                static_cast<uint32_t>(p[3]);
    }

    uint64_t readU64(const uint8_t *p) {
        return (static_cast<uint64_t>(readU32(p)) << 32) | readU32(p + 4);
    }

    std::string ikeExchangeTypeName(uint8_t version, uint8_t exchange) {
        if (version == 1) {
            switch (exchange) {
                case 2: return "Identity Protection (Main Mode)";
                case 4: return "Aggressive Mode";
                case 5: return "Informational";
                case 32: return "Quick Mode";
                case 33: return "New Group Mode";
                default: return "Exchange " + std::to_string(exchange);
            }
        } else { // IKEv2
            switch (exchange) {
                case 34: return "IKE_SA_INIT";
                case 35: return "IKE_AUTH";
                case 36: return "CREATE_CHILD_SA";
                case 37: return "INFORMATIONAL";
                default: return "Exchange " + std::to_string(exchange);
            }
        }
    }

    std::string ikePayloadTypeName(uint8_t version, uint8_t nextPayload) {
        if (nextPayload == 0) return "NONE";
        if (version == 2) {   // RFC 7296 section 3.2 (SKF: RFC 7383)
            switch (nextPayload) {
                case 33: return "Security Association (SA)";
                case 34: return "Key Exchange (KE)";
                case 35: return "Identification - Initiator (IDi)";
                case 36: return "Identification - Responder (IDr)";
                case 37: return "Certificate (CERT)";
                case 38: return "Certificate Request (CERTREQ)";
                case 39: return "Authentication (AUTH)";
                case 40: return "Nonce (Ni, Nr)";
                case 41: return "Notify (N)";
                case 42: return "Delete (D)";
                case 43: return "Vendor ID (V)";
                case 44: return "Traffic Selector - Initiator (TSi)";
                case 45: return "Traffic Selector - Responder (TSr)";
                case 46: return "Encrypted and Authenticated (SK)";
                case 47: return "Configuration (CP)";
                case 48: return "Extensible Authentication (EAP)";
                case 53: return "Encrypted Fragment (SKF)";
                default: return "Payload " + std::to_string(nextPayload);
            }
        }
        switch (nextPayload) {   // RFC 2408 section 3.1
            case 1: return "Security Association (SA)";
            case 2: return "Proposal (P)";
            case 3: return "Transform (T)";
            case 4: return "Key Exchange (KE)";
            case 5: return "Identification (ID)";
            case 6: return "Certificate (CERT)";
            case 7: return "Certificate Request (CR)";
            case 8: return "Hash (HASH)";
            case 9: return "Signature (SIG)";
            case 10: return "Nonce (NONCE)";
            case 11: return "Notification (N)";
            case 12: return "Delete (D)";
            case 13: return "Vendor ID (VID)";
            default: return "Payload " + std::to_string(nextPayload);
        }
    }
} // namespace

void dissect::noteAhHeader(Context &ctx, uint32_t spi, uint32_t sequence) {
    ctx.pack.has_ah = 1;
    if (ctx.mode != ParseMode::Replay && ctx.sessions) {
        ctx.sessions->addIpsecHeader(static_cast<uint32_t>(ctx.pack.number), packet::IpsecTable::kAh, spi, sequence);
    }
}

std::string dissect::ipsecProtocolName(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP (1)";
        case 4: return "IPv4 (4)";
        case 6: return "TCP (6)";
        case 17: return "UDP (17)";
        case 41: return "IPv6 (41)";
        case 47: return "GRE (47)";
        case 50: return "ESP (50)";
        case 51: return "AH (51)";
        case 58: return "ICMPv6 (58)";
        case 59: return "No Next Header (59)";
        case 132: return "SCTP (132)";
        default: return "protocol " + std::to_string(protocol);
    }
}

void dissect::dissectAh(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "AH";
    pack.has_ah = 1;

    if (length < 12) {
        ctx.markMalformed("AH header truncated");
        pack.info = "AH [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const uint8_t nextHeader = bytes[0];
    const uint8_t payloadLen = bytes[1]; // length in 4-byte units, minus 2
    const size_t ahLength = (static_cast<size_t>(payloadLen) + 2) * 4;

    if (ahLength < 12 || length < ahLength) {
        ctx.markMalformed("AH payload length invalid or truncated");
        pack.info = "AH [Malformed Length]";
        return;
    }

    const uint32_t spi = readU32(bytes + 4);
    const uint32_t seq = readU32(bytes + 8);

    noteAhHeader(ctx, spi, seq);
    pack.info = "SPI: " + hexString(spi, 8) + ", Seq: " + std::to_string(seq);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("IPsec Authentication Header (SPI: " + hexString(spi, 8) + ")", o, ahLength);

        l.add("Next Header: " + ipsecProtocolName(nextHeader), o, 1);
        l.add("Payload Length: " + std::to_string(payloadLen) + " (" + std::to_string(ahLength) + " bytes)", o + 1, 1);
        l.add("Reserved", o + 2, 2);
        l.add("Security Parameters Index: " + hexString(spi, 8), o + 4, 4);
        l.add("Sequence Number: " + std::to_string(seq), o + 8, 4);
        if (ahLength > 12) {
            l.add("Integrity Check Value (ICV)", o + 12, ahLength - 12);
        }
    }

    // The protected payload is what the Next Header field names (RFC 4302 3.1.1): the AH is a layer, as the IPv6 extension headers
    // are. The payload length of the IP header drops the AH like it drops an extension header.
    pack.ip_protocol = nextHeader;
    pack.length = pack.length >= ahLength ? pack.length - static_cast<uint32_t>(ahLength) : 0;
    if (length > ahLength) {
        if (const Dissector *inner = ctx.registry.findIpProtocol(nextHeader)) {
            (*inner)(ctx, data + ahLength, length - ahLength);
            return;
        }
    }
    pack.protocol = "AH";   // nothing follows (or nothing we decode)
}

void dissect::dissectEsp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "ESP";

    if (length < 8) {
        ctx.markMalformed("ESP header truncated");
        pack.info = "ESP [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const uint32_t spi = readU32(bytes);
    const uint32_t seq = readU32(bytes + 4);

    pack.tcp_pdu_start = spi;
    pack.app_code = seq;
    pack.info = "SPI: " + hexString(spi, 8) + ", Seq: " + std::to_string(seq) + " (Encrypted payload)";

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Encapsulating Security Payload (SPI: " + hexString(spi, 8) + ")", o, length);

        l.add("Security Parameters Index: " + hexString(spi, 8), o, 4);
        l.add("Sequence Number: " + std::to_string(seq), o + 4, 4);
        if (length > 8) {
            l.add("Encrypted Data and Authentication (" + std::to_string(length - 8) + " bytes)", o + 8, length - 8);
        }
    }
}

namespace {
    // RFC 2408 / RFC 2409 exchange types (and the private range 240..255); RFC 7296 and its extensions for IKEv2.
    bool plausibleExchangeType(uint8_t major, uint8_t exchange) {
        if (exchange >= 240) return true;
        if (major == 1) return exchange <= 6 || exchange == 32 || exchange == 33;
        return exchange >= 34 && exchange <= 44;
    }
} // namespace

void dissect::dissectIke(Context &ctx, const char *data, size_t length) {
    // Ports 500 and 4500 carry more than IKE. This dissector only takes what is IKE and leaves the protocol empty
    // otherwise, so the generic UDP handling applies (see dissectUdp).
    const auto *raw = reinterpret_cast<const uint8_t *>(data);
    const bool natT = ctx.pack.src_port == 4500 || ctx.pack.dst_port == 4500;

    // NAT-Traversal keepalive (RFC 3948): a single 0xFF byte
    if (length == 1 && raw[0] == 0xFF) {
        ctx.pack.protocol = "NAT-Keepalive";
        ctx.pack.info = "NAT-Traversal Keepalive";
        return;
    }

    // On port 4500 a datagram starting with the Non-ESP marker (four zero bytes) is IKE; anything else is ESP in UDP.
    size_t skip = 0;
    if (natT) {
        if (length >= 8 && readU32(raw) != 0) {
            dissectEsp(ctx, data, length);
            return;
        }
        if (length >= 4 && readU32(raw) == 0) skip = 4;
        else return;
    }

    // ISAKMP header (28 bytes): version 1.x or 2.x, a plausible exchange type, and a Length that is the datagram's
    if (length < skip + 19) return;
    const auto *bytes = raw + skip;
    const uint8_t mjVer = bytes[17] >> 4;
    const uint8_t mnVer = bytes[17] & 0x0F;
    const uint8_t exchangeType = bytes[18];
    if ((mjVer != 1 && mjVer != 2) || !plausibleExchangeType(mjVer, exchangeType)) return;
    const size_t declared = ctx.pack.length >= 8 ? ctx.pack.length - 8 : length;   // UDP payload length as declared
    if (declared < skip + 28) return;
    if (length >= skip + 28 && readU32(bytes + 24) != declared - skip) return;

    if (length < skip + 28) {
        ctx.pack.protocol = mjVer == 2 ? "IKEv2" : "ISAKMP";
        ctx.markMalformed("IKE header truncated");
        ctx.pack.info = "IKE [Truncated]";
        return;
    }

    uint64_t initSpi = readU64(bytes);
    uint64_t respSpi = readU64(bytes + 8);
    uint8_t nextPayload = bytes[16];
    uint8_t flags = bytes[19];
    uint32_t msgId = readU32(bytes + 20);
    uint32_t totalLen = readU32(bytes + 24);

    const uint8_t ver = mjVer;
    ctx.pack.protocol = (ver == 2) ? "IKEv2" : "ISAKMP";
    ctx.pack.app_code = ver;
    ctx.pack.app_type = exchangeType;

    std::string exchName = ikeExchangeTypeName(ver, exchangeType);
    ctx.pack.info = (ver == 2 ? "IKEv2 " : "ISAKMP ") + exchName +
                    ", MsgID: " + std::to_string(msgId);

    // Walk the top-level payload chain (in both passes: the verdict is part of the summary). A payload longer than
    // what is left is cut to it and flagged.
    struct Payload { uint8_t type, next; uint16_t length; size_t off, shown; bool tooLong; };
    std::vector<Payload> payloads;
    const size_t avail = length - skip;
    {
        size_t poff = 28;
        uint8_t currentPayload = nextPayload;
        while (currentPayload != 0 && poff + 4 <= avail) {
            const auto *pb = bytes + poff;
            const uint16_t plen = readU16(pb + 2);
            const size_t room = avail - poff;
            const bool tooLong = plen > room;
            payloads.push_back({currentPayload, pb[0], plen, poff, tooLong ? room : plen, tooLong});
            if (plen < 4) { ctx.markMalformed("IKE payload length below the payload header"); break; }
            if (tooLong) { ctx.markMalformed("IKE payload extends beyond the packet"); break; }
            poff += plen;
            currentPayload = pb[0];
        }
    }

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data + skip);
        if (skip) ctx.addLayer("Non-ESP Marker", o - skip, skip);
        Field &l = ctx.addLayer((ver == 2 ? "Internet Key Exchange (IKEv2)" : "Internet Security Association and Key Management Protocol (ISAKMP)"),
                                o, avail);

        l.add("Initiator SPI: 0x" + hexString(initSpi, 16), o, 8);
        l.add("Responder SPI: 0x" + hexString(respSpi, 16), o + 8, 8);
        l.add("Next Payload: " + std::to_string(nextPayload) + " (" + ikePayloadTypeName(ver, nextPayload) + ")", o + 16, 1);
        l.add("Version: " + std::to_string(mjVer) + "." + std::to_string(mnVer), o + 17, 1);
        l.add("Exchange Type: " + std::to_string(exchangeType) + " (" + exchName + ")", o + 18, 1);
        l.add("Flags: " + hexString(flags, 2), o + 19, 1);
        l.add("Message ID: " + std::to_string(msgId), o + 20, 4);
        l.add("Length: " + std::to_string(totalLen), o + 24, 4);

        for (const auto &pl: payloads) {
            Field &pf = l.add("Payload: " + ikePayloadTypeName(ver, pl.type) + " (" + std::to_string(pl.length) + " bytes" +
                              (pl.tooLong ? ", beyond the packet" : "") + ")", o + pl.off, pl.shown);
            pf.add("Next Payload: " + std::to_string(pl.next) + " (" + ikePayloadTypeName(ver, pl.next) + ")", o + pl.off, 1);
            pf.add("Payload Length: " + std::to_string(pl.length), o + pl.off + 2, 2);
        }
    }
}

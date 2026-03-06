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
        switch (nextPayload) {
            case 0: return "NONE";
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
            case 33: return version == 2 ? "Encrypted and Authenticated (SK)" : "Payload 33";
            case 34: return version == 2 ? "Configuration (CP)" : "Payload 34";
            case 35: return version == 2 ? "Extensible Authentication (EAP)" : "Payload 35";
            case 36: return version == 2 ? "Authentication (AUTH)" : "Payload 36";
            default: return "Payload " + std::to_string(nextPayload);
        }
    }
} // namespace

void dissect::dissectAh(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "AH";

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

    pack.tcp_pdu_start = spi;
    pack.app_code = seq;
    pack.info = "SPI: " + hexString(spi, 8) + ", Seq: " + std::to_string(seq);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("IPsec Authentication Header (SPI: " + hexString(spi, 8) + ")", o, ahLength);

        l.add("Next Header: " + std::to_string(nextHeader), o, 1);
        l.add("Payload Length: " + std::to_string(payloadLen) + " (" + std::to_string(ahLength) + " bytes)", o + 1, 1);
        l.add("Reserved", o + 2, 2);
        l.add("Security Parameters Index: " + hexString(spi, 8), o + 4, 4);
        l.add("Sequence Number: " + std::to_string(seq), o + 8, 4);
        if (ahLength > 12) {
            l.add("Integrity Check Value (ICV)", o + 12, ahLength - 12);
        }
    }
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

void dissect::dissectIke(Context &ctx, const char *data, size_t length) {
    // Handle NAT-Traversal keepalive (single byte 0xFF)
    if (length == 1 && static_cast<uint8_t>(data[0]) == 0xFF) {
        ctx.pack.protocol = "NAT-Keepalive";
        ctx.pack.info = "NAT-Traversal Keepalive";
        return;
    }

    // Handle Non-ESP Marker (4 zero bytes in port 4500 encapsulation)
    size_t skip = 0;
    if (length >= 4 && readU32(reinterpret_cast<const uint8_t *>(data)) == 0) {
        skip = 4;
    }

    if (length < skip + 28) {
        ctx.pack.protocol = "ISAKMP";
        ctx.markMalformed("IKE header truncated");
        ctx.pack.info = "IKE [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data + skip);
    uint64_t initSpi = readU64(bytes);
    uint64_t respSpi = readU64(bytes + 8);
    uint8_t nextPayload = bytes[16];
    uint8_t mjVer = bytes[17] >> 4;
    uint8_t mnVer = bytes[17] & 0x0F;
    uint8_t exchangeType = bytes[18];
    uint8_t flags = bytes[19];
    uint32_t msgId = readU32(bytes + 20);
    uint32_t totalLen = readU32(bytes + 24);

    uint8_t ver = (mjVer == 2) ? 2 : 1;
    ctx.pack.protocol = (ver == 2) ? "IKEv2" : "ISAKMP";
    ctx.pack.app_code = ver;
    ctx.pack.app_type = exchangeType;

    std::string exchName = ikeExchangeTypeName(ver, exchangeType);
    ctx.pack.info = (ver == 2 ? "IKEv2 " : "ISAKMP ") + exchName +
                    ", MsgID: " + std::to_string(msgId);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data + skip);
        Field &l = ctx.addLayer((ver == 2 ? "Internet Key Exchange (IKEv2)" : "Internet Security Association and Key Management Protocol (ISAKMP)"),
                                o, length - skip);

        l.add("Initiator SPI: 0x" + hexString(initSpi, 16), o, 8);
        l.add("Responder SPI: 0x" + hexString(respSpi, 16), o + 8, 8);
        l.add("Next Payload: " + std::to_string(nextPayload) + " (" + ikePayloadTypeName(ver, nextPayload) + ")", o + 16, 1);
        l.add("Version: " + std::to_string(mjVer) + "." + std::to_string(mnVer), o + 17, 1);
        l.add("Exchange Type: " + std::to_string(exchangeType) + " (" + exchName + ")", o + 18, 1);
        l.add("Flags: " + hexString(flags, 2), o + 19, 1);
        l.add("Message ID: " + std::to_string(msgId), o + 20, 4);
        l.add("Length: " + std::to_string(totalLen), o + 24, 4);

        // Parse top-level payload chain
        size_t poff = 28;
        uint8_t currentPayload = nextPayload;
        while (currentPayload != 0 && poff + 4 <= (length - skip)) {
            const auto *pb = bytes + poff;
            uint8_t np = pb[0];
            uint16_t plen = readU16(pb + 2);
            std::string pname = ikePayloadTypeName(ver, currentPayload);

            Field &pf = l.add("Payload: " + pname + " (" + std::to_string(plen) + " bytes)", o + poff, plen);
            pf.add("Next Payload: " + std::to_string(np) + " (" + ikePayloadTypeName(ver, np) + ")", o + poff, 1);
            pf.add("Payload Length: " + std::to_string(plen), o + poff + 2, 2);

            if (plen < 4) break;
            poff += plen;
            currentPayload = np;
        }
    }
}

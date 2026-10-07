#include "ppi.h"

#include <algorithm>
#include <sstream>

#include "protocols.h"
#include "registry.h"
#include "util.h"
#include "wlan.h"

using packet::Field;

namespace {
    using dissect::hexString;
    using dissect::le16;
    using dissect::le32;

    const char *ppiTlvTypeName(uint16_t type) {
        switch (type) {
            case 2: return "802.11-Common";
            case 3: return "802.11-MAC Extension";
            case 4: return "802.11-MAC/PHY Extension";
            case 5: return "802.11n-MAC Extension";
            case 6: return "802.11n-MAC/PHY Extension";
            case 7: return "Spectrum-Map";
            case 8: return "Process-Info";
            case 9: return "Capture-Info";
            default: return "Field";
        }
    }
} // namespace

void dissect::dissectPpi(Context &ctx, const char *data, size_t length) {
    if (length < 8) {
        ctx.markMalformed("frame too short for PPI header");
        ctx.pack.protocol = "PPI";
        return;
    }

    const uint8_t version = static_cast<uint8_t>(data[0]);
    const uint8_t flags = static_cast<uint8_t>(data[1]);
    const uint16_t pph_len = le16(data + 2);
    const uint32_t pph_dlt = le32(data + 4);

    if (pph_len < 8 || pph_len > length) {
        ctx.markMalformed("invalid PPI header length");
        ctx.pack.protocol = "PPI";
        return;
    }

    ctx.pack.ppi_dlt = static_cast<uint16_t>(pph_dlt);
    const size_t baseOffset = ctx.offsetOf(data);

    Field *ppiLayer = nullptr;
    if (ctx.wantFields()) {
        ppiLayer = &ctx.addLayer("Packet Processing Information, DLT: " + std::to_string(pph_dlt) + ", Length: " + std::to_string(pph_len),
                                 baseOffset, pph_len);
        ppiLayer->add("Version: " + std::to_string(version), baseOffset, 1);
        ppiLayer->add("Flags: " + hexString(flags, 2), baseOffset + 1, 1);
        ppiLayer->add("Header length: " + std::to_string(pph_len), baseOffset + 2, 2);
        ppiLayer->add("Data Link Type: " + std::to_string(pph_dlt), baseOffset + 4, 4);
    }

    bool fcsIncluded = false;
    size_t cur = 8;
    while (cur + 4 <= pph_len) {
        const uint16_t pfh_type = le16(data + cur);
        const uint16_t pfh_datalen = le16(data + cur + 2);
        if (cur + 4 + pfh_datalen > pph_len) break;

        const char *tlvData = data + cur + 4;
        if (pfh_type == 2 && pfh_datalen >= 20) { // 802.11-Common
            const uint16_t commonFlags = le16(tlvData + 8);
            if (commonFlags & 0x0002) fcsIncluded = true;
            const uint16_t rate = le16(tlvData + 10);
            const uint16_t freq = le16(tlvData + 12);
            const uint16_t chFlags = le16(tlvData + 14);
            const int8_t sigDbm = static_cast<int8_t>(tlvData[18]);
            const int8_t noiseDbm = static_cast<int8_t>(tlvData[19]);

            ctx.pack.radiotap_freq = freq;
            ctx.pack.radiotap_rate = static_cast<uint8_t>(rate);
            ctx.pack.radiotap_signal = sigDbm;

            if (ppiLayer) {
                Field &tlv = ppiLayer->add(std::string(ppiTlvTypeName(pfh_type)) + " (" + std::to_string(pfh_datalen) + " bytes)",
                                          baseOffset + cur, 4 + pfh_datalen);
                tlv.add("Header type: " + std::to_string(pfh_type) + " (" + ppiTlvTypeName(pfh_type) + ")", baseOffset + cur, 2);
                tlv.add("Header length: " + std::to_string(pfh_datalen), baseOffset + cur + 2, 2);

                uint64_t tsft;
                std::memcpy(&tsft, tlvData, 8);
                tlv.add("TSFT Timer: " + std::to_string(tsft) + " us", baseOffset + cur + 4, 8);
                tlv.add("Flags: " + hexString(commonFlags, 4) + (fcsIncluded ? " (FCS included)" : ""), baseOffset + cur + 12, 2);

                std::ostringstream ss;
                ss << (rate * 0.5) << " Mb/s";
                tlv.add("Rate: " + ss.str(), baseOffset + cur + 14, 2);
                tlv.add("Channel frequency: " + std::to_string(freq) + " MHz (Flags: " + hexString(chFlags, 4) + ")", baseOffset + cur + 16, 4);
                tlv.add("Signal strength: " + std::to_string(static_cast<int>(sigDbm)) + " dBm", baseOffset + cur + 22, 1);
                tlv.add("Noise: " + std::to_string(static_cast<int>(noiseDbm)) + " dBm", baseOffset + cur + 23, 1);
            }
        } else if (ppiLayer) {
            Field &tlv = ppiLayer->add(std::string(ppiTlvTypeName(pfh_type)) + " (" + std::to_string(pfh_datalen) + " bytes)",
                                      baseOffset + cur, 4 + pfh_datalen);
            tlv.add("Header type: " + std::to_string(pfh_type) + " (" + ppiTlvTypeName(pfh_type) + ")", baseOffset + cur, 2);
            tlv.add("Header length: " + std::to_string(pfh_datalen), baseOffset + cur + 2, 2);
        }

        cur += 4 + pfh_datalen;
        if (flags & 0x01) { // 32-bit alignment
            cur = (cur + 3) & ~3;
        }
    }

    size_t payloadLen = length - pph_len;
    if (fcsIncluded && payloadLen >= 4) {
        payloadLen -= 4;
    }

    // Dispatch to the encapsulated Data Link Type dissector (e.g. 105 for 802.11)
    if (const Dissector *d = ctx.registry.findLinkType(pph_dlt)) {
        (*d)(ctx, data + pph_len, payloadLen);
    } else {
        ctx.pack.protocol = "PPI";
        ctx.pack.info = "Encapsulated DLT " + std::to_string(pph_dlt) + " (" + std::to_string(payloadLen) + " bytes)";
    }

    if (fcsIncluded && ctx.wantFields() && length >= static_cast<size_t>(pph_len) + 4) {
        ctx.addLayer("Frame Check Sequence: 4 bytes", baseOffset + length - 4, 4);
    }
}

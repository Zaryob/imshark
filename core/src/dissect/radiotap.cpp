#include "radiotap.h"

#include <algorithm>
#include <vector>

#include "protocols.h"
#include "util.h"
#include "wlan.h"

using packet::Field;

namespace {
    using dissect::hexString;
    using dissect::le16;
    using dissect::le32;
} // namespace

void dissect::dissectRadiotap(Context &ctx, const char *data, size_t length) {
    if (length < 8) {
        ctx.markMalformed("frame too short for Radiotap header");
        ctx.pack.protocol = "Radiotap";
        return;
    }

    const uint8_t version = static_cast<uint8_t>(data[0]);
    const uint16_t it_len = le16(data + 2);
    if (it_len < 8 || it_len > length) {
        ctx.markMalformed("invalid Radiotap header length");
        ctx.pack.protocol = "Radiotap";
        return;
    }

    const size_t baseOffset = ctx.offsetOf(data);

    // Read present bitmasks
    std::vector<uint32_t> masks;
    size_t maskOff = 4;
    while (maskOff + 4 <= it_len) {
        const uint32_t m = le32(data + maskOff);
        masks.push_back(m);
        maskOff += 4;
        if ((m & (1u << 31)) == 0) break;
    }

    const uint32_t m0 = !masks.empty() ? masks[0] : 0;
    size_t cur = maskOff;
    auto align = [&](size_t a) {
        cur = (cur + a - 1) & ~(a - 1);
    };

    bool haveTsft = false;
    uint64_t tsft = 0;
    bool haveFlags = false;
    uint8_t flags = 0;
    bool fcsAtEnd = false;
    bool haveRate = false;
    uint8_t rate = 0;
    bool haveChannel = false;
    uint16_t freq = 0;
    uint16_t chFlags = 0;
    bool haveSignal = false;
    int8_t signalDbm = 0;
    bool haveNoise = false;
    int8_t noiseDbm = 0;
    bool haveAntenna = false;
    uint8_t antenna = 0;

    // Bit 0: TSFT (8 bytes, align 8)
    if (m0 & (1u << 0)) {
        align(8);
        if (cur + 8 <= it_len) {
            haveTsft = true;
            std::memcpy(&tsft, data + cur, 8);
            cur += 8;
        }
    }

    // Bit 1: Flags (1 byte, align 1)
    if (m0 & (1u << 1)) {
        if (cur + 1 <= it_len) {
            haveFlags = true;
            flags = static_cast<uint8_t>(data[cur++]);
            fcsAtEnd = (flags & 0x10) != 0;
        }
    }

    // Bit 2: Rate (1 byte, align 1)
    if (m0 & (1u << 2)) {
        if (cur + 1 <= it_len) {
            haveRate = true;
            rate = static_cast<uint8_t>(data[cur++]);
            ctx.pack.radiotap_rate = rate;
        }
    }

    // Bit 3: Channel (4 bytes, align 2)
    if (m0 & (1u << 3)) {
        align(2);
        if (cur + 4 <= it_len) {
            haveChannel = true;
            freq = le16(data + cur);
            chFlags = le16(data + cur + 2);
            cur += 4;
            ctx.pack.radiotap_freq = freq;
        }
    }

    // Bit 4: FHSS (2 bytes, align 2)
    if (m0 & (1u << 4)) {
        align(2);
        if (cur + 2 <= it_len) cur += 2;
    }

    // Bit 5: dBm Antenna Signal (1 byte, align 1)
    if (m0 & (1u << 5)) {
        if (cur + 1 <= it_len) {
            haveSignal = true;
            signalDbm = static_cast<int8_t>(data[cur++]);
            ctx.pack.radiotap_signal = signalDbm;
        }
    }

    // Bit 6: dBm Antenna Noise (1 byte, align 1)
    if (m0 & (1u << 6)) {
        if (cur + 1 <= it_len) {
            haveNoise = true;
            noiseDbm = static_cast<int8_t>(data[cur++]);
        }
    }

    // Bit 7: Lock Quality (2 bytes, align 2)
    if (m0 & (1u << 7)) {
        align(2);
        if (cur + 2 <= it_len) cur += 2;
    }

    // Bit 8: TX Attenuation (2 bytes, align 2)
    if (m0 & (1u << 8)) {
        align(2);
        if (cur + 2 <= it_len) cur += 2;
    }

    // Bit 9: dB TX Attenuation (2 bytes, align 2)
    if (m0 & (1u << 9)) {
        align(2);
        if (cur + 2 <= it_len) cur += 2;
    }

    // Bit 10: dBm TX Power (1 byte, align 1)
    if (m0 & (1u << 10)) {
        if (cur + 1 <= it_len) cur += 1;
    }

    // Bit 11: Antenna (1 byte, align 1)
    if (m0 & (1u << 11)) {
        if (cur + 1 <= it_len) {
            haveAntenna = true;
            antenna = static_cast<uint8_t>(data[cur++]);
        }
    }

    if (ctx.wantFields()) {
        Field &rt = ctx.addLayer("Radiotap Header v" + std::to_string(version) + ", Length " + std::to_string(it_len),
                                 baseOffset, it_len);
        rt.add("Header version: " + std::to_string(version), baseOffset, 1);
        rt.add("Header pad: " + std::to_string(static_cast<uint8_t>(data[1])), baseOffset + 1, 1);
        rt.add("Header length: " + std::to_string(it_len), baseOffset + 2, 2);
        for (size_t i = 0; i < masks.size(); ++i) {
            rt.add("Present flags word " + std::to_string(i) + ": " + hexString(masks[i], 8), baseOffset + 4 + i * 4, 4);
        }
        if (haveTsft) rt.add("MAC timestamp: " + std::to_string(tsft) + " us", baseOffset + 8, 8);
        if (haveFlags) {
            Field &f = rt.add("Flags: " + hexString(flags, 2), baseOffset, 1);
            f.add(std::string(".... ...") + ((flags & 0x01) ? "1 = CFP" : "0 = Not CFP"));
            f.add(std::string(".... ..") + ((flags & 0x02) ? "1. = Short Preamble" : "0. = Long Preamble"));
            f.add(std::string(".... .") + ((flags & 0x04) ? "1.. = WEP" : "0.. = No WEP"));
            f.add(std::string(".... ") + ((flags & 0x08) ? "1... = Fragmentation" : "0... = Not fragmented"));
            f.add(std::string("... ") + ((flags & 0x10) ? "1.... = FCS at end" : "0.... = No FCS"));
            f.add(std::string(".. ") + ((flags & 0x20) ? "1..... = Data Pad" : "0..... = No Data Pad"));
            f.add(std::string(". ") + ((flags & 0x40) ? "1...... = Bad FCS" : "0...... = Good FCS"));
            f.add(std::string((flags & 0x80) ? "1....... = Short GI" : "0....... = Long GI"));
        }
        if (haveRate) {
            std::ostringstream ss;
            ss << (rate * 0.5) << " Mb/s";
            rt.add("Data Rate: " + ss.str(), baseOffset, 1);
        }
        if (haveChannel) {
            Field &ch = rt.add("Channel: " + std::to_string(freq) + " MHz (Flags: " + hexString(chFlags, 4) + ")", baseOffset, 4);
            ch.add("Channel frequency: " + std::to_string(freq) + " MHz", baseOffset, 2);
            ch.add("Channel flags: " + hexString(chFlags, 4), baseOffset + 2, 2);
        }
        if (haveSignal) rt.add("SSI Signal: " + std::to_string(static_cast<int>(signalDbm)) + " dBm", baseOffset, 1);
        if (haveNoise) rt.add("SSI Noise: " + std::to_string(static_cast<int>(noiseDbm)) + " dBm", baseOffset, 1);
        if (haveAntenna) rt.add("Antenna: " + std::to_string(antenna), baseOffset, 1);
    }

    size_t wlanLen = length - it_len;
    if (fcsAtEnd && wlanLen >= 4) {
        wlanLen -= 4;
    }

    // Delegate payload to IEEE 802.11 dissector
    dissectIeee80211(ctx, data + it_len, wlanLen);

    if (fcsAtEnd && ctx.wantFields() && length >= static_cast<size_t>(it_len) + 4) {
        ctx.addLayer("Frame Check Sequence: 4 bytes", baseOffset + length - 4, 4);
    }
}

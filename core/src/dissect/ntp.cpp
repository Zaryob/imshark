// NTP (RFC 5905): the 48-byte packet with its timestamps.
#include "protocols.h"

#include "util.h"

#include <network/timeutil.h>

using packet::Field;

namespace {
    using namespace dissect;

    constexpr double kNtpToUnix = 2208988800.0; // seconds between 1900-01-01 and 1970-01-01

    const char *modeName(unsigned m) {
        switch (m) {
            case 1: return "symmetric active";
            case 2: return "symmetric passive";
            case 3: return "client";
            case 4: return "server";
            case 5: return "broadcast";
            case 6: return "control message";
            case 7: return "private message";
            default: return "reserved";
        }
    }

    std::string timestamp(const char *d) {
        const uint32_t secs = be32(d), frac = be32(d + 4);
        if (secs == 0 && frac == 0) return "Not set";
        return network::formatUtcTime(static_cast<double>(secs) - kNtpToUnix + static_cast<double>(frac) / 4294967296.0) + " UTC";
    }

    const char *controlOpcode(unsigned op) {
        switch (op) {
            case 1: return "read status";
            case 2: return "read variables";
            case 3: return "write variables";
            case 4: return "read clock variables";
            case 5: return "write clock variables";
            case 6: return "set trap";
            case 7: return "trap response";
            case 8: return "configure";
            case 9: return "save configuration";
            case 10: return "read MRU list";
            case 11: return "read ordered list";
            case 12: return "request nonce";
            case 31: return "unset trap";
            default: return "unknown";
        }
    }

    const char *privateRequest(unsigned code) {
        switch (code) {
            case 0: return "PEER_LIST";
            case 1: return "PEER_LIST_SUM";
            case 2: return "PEER_INFO";
            case 3: return "PEER_STATS";
            case 4: return "SYS_INFO";
            case 5: return "SYS_STATS";
            case 6: return "IO_STATS";
            case 7: return "MEM_STATS";
            case 8: return "LOOP_INFO";
            case 9: return "TIMER_STATS";
            case 10: return "CONFIG";
            case 11: return "UNCONFIG";
            case 42: return "REQ_MON_GETLIST_1";
            case 20: return "GET_RESTRICT";
            default: return "request";
        }
    }

    std::string fixed1616(const char *d) { return std::to_string(static_cast<double>(be32(d)) / 65536.0) + " seconds"; }
} // namespace

namespace {
    void dissectNtpMessage(Context &ctx, const char *data, size_t length);
}

void dissect::dissectNtp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "NTP";
    if (length >= 1 && ((static_cast<uint8_t>(data[0]) & 7) == 6 || (static_cast<uint8_t>(data[0]) & 7) == 7)) {
        dissectNtpMessage(ctx, data, length);
        return;
    }
    if (length < 48) {
        ctx.markMalformed("NTP packet shorter than 48 bytes");
        return;
    }
    const uint8_t b0 = static_cast<uint8_t>(data[0]);
    const unsigned leap = b0 >> 6, version = (b0 >> 3) & 7, mode = b0 & 7;
    const unsigned stratum = static_cast<uint8_t>(data[1]);
    pack.app_type = static_cast<uint16_t>(mode);
    pack.app_code = static_cast<uint16_t>(stratum);
    pack.app_flags = static_cast<uint16_t>(version);
    pack.info = "NTP Version " + std::to_string(version) + ", " + modeName(mode);

    if (!ctx.wantFields()) return;
    const size_t o = ctx.offsetOf(data);
    Field &l = ctx.addLayer("Network Time Protocol (" + std::string(modeName(mode)) + ")", o, length);
    static const char *leapText[] = {"no warning", "last minute has 61 seconds", "last minute has 59 seconds", "unknown (clock unsynchronized)"};
    l.add(std::string("Flags: Leap Indicator: ") + leapText[leap] + ", Version: " + std::to_string(version) + ", Mode: " + modeName(mode) +
              " (" + std::to_string(mode) + ")", o, 1);
    l.add("Peer Clock Stratum: " + std::to_string(stratum) + (stratum == 0 ? " (unspecified or invalid)" : stratum == 1 ? " (primary reference)" : " (secondary reference)"), o + 1, 1);
    l.add("Peer Polling Interval: " + std::to_string(static_cast<uint8_t>(data[2])), o + 2, 1);
    l.add("Peer Clock Precision: " + std::to_string(static_cast<int8_t>(data[3])), o + 3, 1);
    l.add("Root Delay: " + fixed1616(data + 4), o + 4, 4);
    l.add("Root Dispersion: " + fixed1616(data + 8), o + 8, 4);
    std::string refId;
    if (stratum <= 1) {
        for (int i = 0; i < 4; ++i) if (data[12 + i] >= 32 && data[12 + i] < 127) refId += data[12 + i];
    } else {
        refId = ip4(data + 12);
    }
    l.add("Reference ID: " + refId, o + 12, 4);
    l.add("Reference Timestamp: " + timestamp(data + 16), o + 16, 8);
    l.add("Origin Timestamp: " + timestamp(data + 24), o + 24, 8);
    l.add("Receive Timestamp: " + timestamp(data + 32), o + 32, 8);
    l.add("Transmit Timestamp: " + timestamp(data + 40), o + 40, 8);

    // what follows the 48 bytes: extension fields (RFC 7822) and/or a message authentication code
    size_t at = 48;
    int count = 0;
    while (at < length && count++ < 16) {
        const size_t rem = length - at;
        if (rem == 20 || rem == 24) {   // key identifier + MD5 (16) or SHA-1 (20) digest
            Field &mac = l.add(std::string("Message Authentication Code (") + (rem == 20 ? "MD5" : "SHA-1") + ")", o + at, rem);
            mac.add("Key ID: " + std::to_string(be32(data + at)), o + at, 4);
            mac.add("Message Digest: " + std::to_string(rem - 4) + " bytes", o + at + 4, rem - 4);
            at = length;
            break;
        }
        if (rem == 4) { l.add("Key ID: " + std::to_string(be32(data + at)) + " (crypto-NAK if zero)", o + at, 4); at = length; break; }
        if (rem < 4) break;
        const unsigned type = be16(data + at), len = be16(data + at + 2);
        if (len < 4 || len % 4 != 0 || len > rem) { l.add("[Malformed extension field]", o + at, rem); at = length; break; }
        Field &ext = l.add("Extension Field: type " + hexString(type, 4) + ", length " + std::to_string(len), o + at, len);
        ext.add("Field Type: " + hexString(type, 4), o + at, 2);
        ext.add("Field Length: " + std::to_string(len), o + at + 2, 2);
        if (len > 4) ext.add("Value: " + std::to_string(len - 4) + " bytes", o + at + 4, len - 4);
        at += len;
    }
    if (at < length) l.add("Trailing data (" + std::to_string(length - at) + " bytes)", o + at, length - at);
}

namespace {
    // Mode 6 (control, RFC 1305 appendix B) and mode 7 (private, ntpd's ntpdc interface)
    void dissectNtpMessage(Context &ctx, const char *data, size_t length) {
        auto &pack = ctx.pack;
        const uint8_t b0 = static_cast<uint8_t>(data[0]);
        const unsigned version = (b0 >> 3) & 7, mode = b0 & 7;
        pack.app_type = static_cast<uint16_t>(mode);
        pack.app_flags = static_cast<uint16_t>(version);
        const size_t o = ctx.offsetOf(data);

        if (mode == 6) {
            if (length < 12) { ctx.markMalformed("NTP control message shorter than 12 bytes"); return; }
            const uint8_t b1 = static_cast<uint8_t>(data[1]);
            const unsigned opcode = b1 & 0x1f;
            const bool response = b1 & 0x80, error = b1 & 0x40, more = b1 & 0x20;
            const unsigned count = be16(data + 10);
            pack.app_code = static_cast<uint16_t>(opcode);
            pack.info = "NTP Version " + std::to_string(version) + ", control message, " + controlOpcode(opcode) + (response ? " response" : " request") + (error ? " (error)" : "");
            if (!ctx.wantFields()) return;
            Field &l = ctx.addLayer("Network Time Protocol (control message)", o, length);
            l.add("Flags: Version: " + std::to_string(version) + ", Mode: control message (6)", o, 1);
            Field &op = l.add(std::string("Opcode byte: ") + (response ? "response" : "request") + (error ? ", error" : "") + (more ? ", more" : "") + ", " + controlOpcode(opcode) + " (" + std::to_string(opcode) + ")", o + 1, 1);
            op.add(std::string("Response bit: ") + (response ? "Response" : "Request"), o + 1, 1);
            op.add(std::string("Error bit: ") + (error ? "Error" : "No error"), o + 1, 1);
            op.add(std::string("More bit: ") + (more ? "More data follows" : "Last fragment"), o + 1, 1);
            l.add("Sequence: " + std::to_string(be16(data + 2)), o + 2, 2);
            l.add("Status: " + hexString(be16(data + 4), 4), o + 4, 2);
            l.add("Association ID: " + std::to_string(be16(data + 6)), o + 6, 2);
            l.add("Offset: " + std::to_string(be16(data + 8)), o + 8, 2);
            l.add("Count: " + std::to_string(count), o + 10, 2);
            const size_t have = std::min<size_t>(count, length - 12);
            if (count > 0) {
                std::string text(data + 12, have);
                for (auto &c: text) if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) >= 127) c = '.';
                l.add("Data: " + text.substr(0, 200) + (text.size() > 200 ? "..." : ""), o + 12, have);
                if (have < count) l.add("[Data continues past the end of the message]", o + 12 + have, length - 12 - have);
            }
            const size_t padded = (12 + count + 3) / 4 * 4;   // the data is padded to a multiple of 4 bytes
            if (padded <= length && length - padded >= 12) {   // key id + 16 byte digest (or more)
                Field &mac = l.add("Authenticator", o + padded, length - padded);
                mac.add("Key ID: " + std::to_string(be32(data + padded)), o + padded, 4);
                mac.add("Message Digest: " + std::to_string(length - padded - 4) + " bytes", o + padded + 4, length - padded - 4);
            }
            return;
        }

        // mode 7
        if (length < 8) { ctx.markMalformed("NTP private message shorter than 8 bytes"); return; }
        const uint8_t b1 = static_cast<uint8_t>(data[1]);
        const unsigned implementation = static_cast<uint8_t>(data[2]), request = static_cast<uint8_t>(data[3]);
        const unsigned items = be16(data + 4) & 0x0fff, itemSize = be16(data + 6) & 0x0fff, errorCode = be16(data + 4) >> 12;
        const bool response = b0 & 0x80;
        pack.app_code = static_cast<uint16_t>(request);
        pack.info = "NTP Version " + std::to_string(version) + ", private message, " + privateRequest(request) + (response ? " response" : " request");
        if (!ctx.wantFields()) return;
        Field &l = ctx.addLayer("Network Time Protocol (private message)", o, length);
        l.add(std::string("Flags: ") + (response ? "Response" : "Request") + ", Version: " + std::to_string(version) + ", Mode: private message (7)", o, 1);
        l.add(std::string("Authenticated: ") + ((b1 & 0x80) ? "yes" : "no") + ", Sequence: " + std::to_string(b1 & 0x7f), o + 1, 1);
        l.add("Implementation: " + std::to_string(implementation), o + 2, 1);
        l.add(std::string("Request code: ") + privateRequest(request) + " (" + std::to_string(request) + ")", o + 3, 1);
        l.add("Error code: " + std::to_string(errorCode), o + 4, 1);
        l.add("Number of data items: " + std::to_string(items), o + 4, 2);
        l.add("Size of data item: " + std::to_string(itemSize), o + 6, 2);
        if (length > 8) {
            const size_t expected = static_cast<size_t>(items) * itemSize;
            l.add("Data (" + std::to_string(length - 8) + " bytes" + (expected && expected != length - 8 ? ", items announce " + std::to_string(expected) : "") + ")", o + 8, length - 8);
        }
    }
} // namespace

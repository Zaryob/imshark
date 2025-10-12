#include "protocols.h"

#include "reader.h"
#include "util.h"

#include <cstring>
#include <string>
#include <vector>

namespace dissect {

namespace {

const char *sshMessageName(uint8_t msg) {
    switch (msg) {
        case 1: return "SSH_MSG_DISCONNECT";
        case 2: return "SSH_MSG_IGNORE";
        case 3: return "SSH_MSG_UNIMPLEMENTED";
        case 4: return "SSH_MSG_DEBUG";
        case 5: return "SSH_MSG_SERVICE_REQUEST";
        case 6: return "SSH_MSG_SERVICE_ACCEPT";
        case 20: return "SSH_MSG_KEXINIT";
        case 21: return "SSH_MSG_NEWKEYS";
        case 30: return "SSH_MSG_KEXDH_INIT / SSH_MSG_KEX_ECDH_INIT";
        case 31: return "SSH_MSG_KEXDH_REPLY / SSH_MSG_KEX_ECDH_REPLY";
        case 50: return "SSH_MSG_USERAUTH_REQUEST";
        case 51: return "SSH_MSG_USERAUTH_FAILURE";
        case 52: return "SSH_MSG_USERAUTH_SUCCESS";
        case 53: return "SSH_MSG_USERAUTH_BANNER";
        case 80: return "SSH_MSG_GLOBAL_REQUEST";
        case 81: return "SSH_MSG_REQUEST_SUCCESS";
        case 82: return "SSH_MSG_REQUEST_FAILURE";
        case 90: return "SSH_MSG_CHANNEL_OPEN";
        case 91: return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
        case 92: return "SSH_MSG_CHANNEL_OPEN_FAILURE";
        case 93: return "SSH_MSG_CHANNEL_WINDOW_ADJUST";
        case 94: return "SSH_MSG_CHANNEL_DATA";
        case 95: return "SSH_MSG_CHANNEL_EXTENDED_DATA";
        case 96: return "SSH_MSG_CHANNEL_EOF";
        case 97: return "SSH_MSG_CHANNEL_CLOSE";
        case 98: return "SSH_MSG_CHANNEL_REQUEST";
        case 99: return "SSH_MSG_CHANNEL_SUCCESS";
        case 100: return "SSH_MSG_CHANNEL_FAILURE";
        default: return "Unknown SSH Message";
    }
}

std::string trimCrlf(const std::string &s) {
    size_t end = s.size();
    while (end > 0 && (s[end - 1] == '\r' || s[end - 1] == '\n')) --end;
    return s.substr(0, end);
}

std::string firstToken(const std::string &commaList) {
    size_t sp = commaList.find(',');
    return sp != std::string::npos ? commaList.substr(0, sp) : commaList;
}

} // namespace

void dissectSsh(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "SSH";
    if (length == 0) return;

    packet::Field *layer = nullptr;
    const size_t baseOffset = ctx.offsetOf(data);
    if (ctx.wantFields()) {
        layer = &ctx.addLayer("SSH (Secure Shell Protocol)", baseOffset, length);
    }

    size_t offset = 0;
    std::vector<std::string> summaries;

    while (offset < length) {
        // Check if banner (identification string)
        if (length - offset >= 4 && std::memcmp(data + offset, "SSH-", 4) == 0) {
            size_t end = offset;
            while (end < length && data[end] != '\n') ++end;
            if (end < length && data[end] == '\n') ++end; // include newline

            const size_t bannerLen = end - offset;
            const std::string rawBanner(data + offset, bannerLen);
            const std::string banner = trimCrlf(rawBanner);

            if (ctx.pack.app_text.empty()) ctx.pack.app_text = banner;
            summaries.push_back("Protocol: " + banner);

            if (layer) {
                packet::Field &bField = layer->add("Identification String: " + banner, baseOffset + offset, bannerLen);
                size_t dash1 = banner.find('-');
                size_t dash2 = (dash1 != std::string::npos) ? banner.find('-', dash1 + 1) : std::string::npos;
                if (dash1 != std::string::npos && dash2 != std::string::npos) {
                    std::string proto = banner.substr(dash1 + 1, dash2 - dash1 - 1);
                    std::string software = banner.substr(dash2 + 1);
                    bField.add("Protocol Version: " + proto, baseOffset + offset + dash1 + 1, proto.size());
                    bField.add("Software Version: " + software, baseOffset + offset + dash2 + 1, software.size());
                }
            }
            offset = end;
            continue;
        }

        // Binary packet protocol (RFC 4253)
        if (length - offset < 5) {
            const size_t rem = length - offset;
            if (layer) {
                layer->add("Encrypted packet data (" + std::to_string(rem) + " bytes)",
                           baseOffset + offset, rem);
            }
            if (ctx.pack.app_type == 0) ctx.pack.app_type = 255;
            summaries.push_back("Encrypted packet (" + std::to_string(rem) + " bytes)");
            break;
        }

        const uint32_t packetLen = be32(data + offset);
        const uint8_t paddingLen = static_cast<uint8_t>(data[offset + 4]);

        if (packetLen < 2 || packetLen > 65536 || paddingLen >= packetLen || offset + 4 + packetLen > length) {
            const size_t rem = length - offset;
            if (layer) {
                packet::Field &encField = layer->add("Encrypted packet (" + std::to_string(rem) + " bytes)",
                                                     baseOffset + offset, rem);
                encField.add("Encrypted packet payload — decryption not supported", baseOffset + offset, rem);
            }
            if (ctx.pack.app_type == 0) ctx.pack.app_type = 255;
            summaries.push_back("Encrypted packet (" + std::to_string(rem) + " bytes)");
            break;
        }

        const size_t totalPacketBytes = 4 + packetLen;
        const size_t payloadLen = packetLen - 1 - paddingLen;
        const char *payload = data + offset + 5;

        if (payloadLen > 0) {
            const uint8_t msgCode = static_cast<uint8_t>(payload[0]);
            if (ctx.pack.app_type == 0) ctx.pack.app_type = msgCode;

            if (msgCode == 20) { // SSH_MSG_KEXINIT
                summaries.push_back("Key Exchange Init");
                if (layer) {
                    packet::Field &pktField = layer->add("Key Exchange Init (SSH_MSG_KEXINIT)", baseOffset + offset, totalPacketBytes);
                    pktField.add("Packet Length: " + std::to_string(packetLen), baseOffset + offset, 4);
                    pktField.add("Padding Length: " + std::to_string(paddingLen), baseOffset + offset + 4, 1);
                    pktField.add("Message Code: SSH_MSG_KEXINIT (20)", baseOffset + offset + 5, 1);

                    ByteReader r(payload + 1, payloadLen - 1);
                    if (r.remaining() >= 16) {
                        pktField.add("Cookie: " + hexString(be32(payload + 1), 8) + "...", baseOffset + offset + 6, 16);
                        r.skip(16);
                    }

                    auto readNameList = [&](const char *label, std::string *outFirst = nullptr) {
                        if (r.remaining() >= 4 && r.ok()) {
                            const size_t listStart = baseOffset + offset + 5 + 1 + r.pos();
                            const uint32_t strLen = r.u32();
                            if (r.remaining() >= strLen && r.ok()) {
                                std::string val = r.readString(strLen);
                                pktField.add(std::string(label) + ": " + val, listStart, 4 + strLen);
                                if (outFirst && !val.empty()) *outFirst = firstToken(val);
                            }
                        }
                    };

                    std::string kexAlg, encAlg, macAlg;
                    readNameList("KEX Algorithms", &kexAlg);
                    readNameList("Server Host Key Algorithms");
                    readNameList("Encryption Algorithms (Client to Server)", &encAlg);
                    readNameList("Encryption Algorithms (Server to Client)");
                    readNameList("MAC Algorithms (Client to Server)", &macAlg);
                    readNameList("MAC Algorithms (Server to Client)");
                    readNameList("Compression Algorithms (Client to Server)");
                    readNameList("Compression Algorithms (Server to Client)");
                    readNameList("Languages (Client to Server)");
                    readNameList("Languages (Server to Client)");

                    if (!kexAlg.empty()) ctx.pack.app_text = kexAlg;
                    if (!encAlg.empty()) ctx.pack.app_text2 = encAlg;
                }
            } else if (msgCode == 21) { // SSH_MSG_NEWKEYS
                summaries.push_back("New Keys");
                if (layer) {
                    packet::Field &pktField = layer->add("New Keys (SSH_MSG_NEWKEYS)", baseOffset + offset, totalPacketBytes);
                    pktField.add("Packet Length: " + std::to_string(packetLen), baseOffset + offset, 4);
                    pktField.add("Padding Length: " + std::to_string(paddingLen), baseOffset + offset + 4, 1);
                    pktField.add("Message Code: SSH_MSG_NEWKEYS (21)", baseOffset + offset + 5, 1);
                }
            } else if (msgCode == 30) { // DH / ECDH INIT
                summaries.push_back("Key Exchange Init (DH/ECDH)");
                if (layer) {
                    packet::Field &pktField = layer->add("Diffie-Hellman Key Exchange Init (30)", baseOffset + offset, totalPacketBytes);
                    pktField.add("Packet Length: " + std::to_string(packetLen), baseOffset + offset, 4);
                    pktField.add("Message Code: " + std::to_string(msgCode), baseOffset + offset + 5, 1);
                }
            } else if (msgCode == 31) { // DH / ECDH REPLY
                summaries.push_back("Key Exchange Reply (DH/ECDH)");
                if (layer) {
                    packet::Field &pktField = layer->add("Diffie-Hellman Key Exchange Reply (31)", baseOffset + offset, totalPacketBytes);
                    pktField.add("Packet Length: " + std::to_string(packetLen), baseOffset + offset, 4);
                    pktField.add("Message Code: " + std::to_string(msgCode), baseOffset + offset + 5, 1);
                }
            } else {
                summaries.push_back(std::string(sshMessageName(msgCode)));
                if (layer) {
                    packet::Field &pktField = layer->add(std::string(sshMessageName(msgCode)) + " (" + std::to_string(msgCode) + ")",
                                                         baseOffset + offset, totalPacketBytes);
                    pktField.add("Packet Length: " + std::to_string(packetLen), baseOffset + offset, 4);
                    pktField.add("Message Code: " + std::to_string(msgCode), baseOffset + offset + 5, 1);
                }
            }
        }

        offset += totalPacketBytes;
    }

    if (!summaries.empty()) {
        std::string info;
        for (size_t s = 0; s < summaries.size(); ++s) {
            if (s > 0) info += ", ";
            info += summaries[s];
            if (info.size() > 80 && s + 1 < summaries.size()) {
                info += "...";
                break;
            }
        }
        ctx.pack.info = info;
    } else {
        ctx.pack.info = "SSH payload (" + std::to_string(length) + " bytes)";
    }
}

} // namespace dissect

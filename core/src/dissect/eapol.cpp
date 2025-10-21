#include "eapol.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "protocols.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;
    using dissect::hexString;

    std::string bytesToHex(const char *data, size_t len) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(static_cast<uint8_t>(data[i]));
        }
        return ss.str();
    }

    const char *eapolTypeName(uint8_t type) {
        switch (type) {
            case 0: return "EAP Packet";
            case 1: return "Start";
            case 2: return "Logoff";
            case 3: return "Key";
            case 4: return "Encapsulated ASF Alert";
            case 5: return "MKA";
            case 6: return "Announcement-Req";
            case 7: return "Announcement";
            default: return "Unknown";
        }
    }

    const char *keyDescriptorTypeName(uint8_t type) {
        switch (type) {
            case 1: return "RC4 Key Descriptor";
            case 2: return "IEEE 802.11i / RSN Key Descriptor";
            case 254: return "WPA Key Descriptor";
            default: return "Unknown Key Descriptor";
        }
    }

    const char *eapCodeName(uint8_t code) {
        switch (code) {
            case 1: return "Request";
            case 2: return "Response";
            case 3: return "Success";
            case 4: return "Failure";
            default: return "Unknown";
        }
    }

    const char *eapTypeName(uint8_t type) {
        switch (type) {
            case 1: return "Identity";
            case 2: return "Notification";
            case 3: return "Nak (Response only)";
            case 4: return "MD5-Challenge";
            case 5: return "One-Time Password";
            case 6: return "Generic Token Card";
            case 13: return "EAP-TLS";
            case 17: return "LEAP";
            case 18: return "EAP-SIM";
            case 21: return "EAP-TTLS";
            case 25: return "PEAP";
            case 43: return "EAP-FAST";
            default: return "Unknown";
        }
    }
} // namespace

void dissect::dissectEapol(Context &ctx, const char *data, size_t length) {
    if (length < 4) {
        ctx.markMalformed("frame too short for 802.1X header");
        ctx.pack.protocol = "EAPOL";
        return;
    }

    const uint8_t version = static_cast<uint8_t>(data[0]);
    const uint8_t type = static_cast<uint8_t>(data[1]);
    const uint16_t bodyLen = be16(data + 2);

    ctx.pack.app_type = type; // eapol.type
    ctx.pack.protocol = (type == 0 ? "EAP" : "EAPOL");

    const size_t baseOffset = ctx.offsetOf(data);
    const size_t totalDeclared = 4 + bodyLen;
    const size_t actualSpan = std::min(length, totalDeclared);

    Field *eapolLayer = nullptr;
    if (ctx.wantFields()) {
        std::string verStr;
        switch (version) {
            case 1: verStr = "802.1X-2001 (1)"; break;
            case 2: verStr = "802.1X-2004 (2)"; break;
            case 3: verStr = "802.1X-2010 (3)"; break;
            default: verStr = std::to_string(version); break;
        }

        eapolLayer = &ctx.addLayer("IEEE 802.1X Authentication", baseOffset, actualSpan);
        eapolLayer->add("Version: " + verStr, baseOffset, 1);
        eapolLayer->add("Type: " + std::string(eapolTypeName(type)) + " (" + std::to_string(type) + ")", baseOffset + 1, 1);
        eapolLayer->add("Length: " + std::to_string(bodyLen), baseOffset + 2, 2);
    }

    // ---------------------------------------------------------------------------------------------
    // EAPOL-Start / EAPOL-Logoff
    // ---------------------------------------------------------------------------------------------
    if (type == 1) {
        ctx.pack.info = "EAPOL-Start";
        return;
    }
    if (type == 2) {
        ctx.pack.info = "EAPOL-Logoff";
        return;
    }

    // ---------------------------------------------------------------------------------------------
    // EAPOL-Key (Type 3)
    // ---------------------------------------------------------------------------------------------
    if (type == 3) {
        if (length < 5) {
            ctx.markMalformed("truncated EAPOL-Key header");
            return;
        }

        const uint8_t descType = static_cast<uint8_t>(data[4]);
        ctx.pack.app_code = descType; // eapol.keydes.type

        if (descType == 2 || descType == 254) { // IEEE 802.11i / RSN or WPA
            if (length < 99) { // 4 bytes 802.1X + 95 bytes fixed Key header
                ctx.markMalformed("truncated RSN/WPA Key Descriptor");
                return;
            }

            const char *k = data + 4;
            const uint16_t keyInfo = be16(k + 1);
            const uint16_t keyLen = be16(k + 3);

            uint64_t replay = 0;
            for (int i = 0; i < 8; ++i) {
                replay = (replay << 8) | static_cast<uint8_t>(k[5 + i]);
            }

            const char *nonce = k + 13;
            const char *iv = k + 45;
            const char *rsc = k + 61;
            const char *id = k + 69;
            const char *mic = k + 77;
            const uint16_t keyDataLen = be16(k + 93);

            const uint8_t keyDescVer = keyInfo & 0x0007;
            const bool keyType = (keyInfo & 0x0008) != 0; // 1 = Pairwise, 0 = Group
            const uint8_t keyIndex = (keyInfo >> 4) & 0x03;
            const bool install = (keyInfo & 0x0040) != 0;
            const bool keyAck = (keyInfo & 0x0080) != 0;
            const bool keyMic = (keyInfo & 0x0100) != 0;
            const bool secure = (keyInfo & 0x0200) != 0;
            const bool error = (keyInfo & 0x0400) != 0;
            const bool request = (keyInfo & 0x0800) != 0;
            const bool encrypted = (keyInfo & 0x1000) != 0;
            const bool smk = (keyInfo & 0x2000) != 0;

            uint8_t msgNr = 0;
            std::string msgDesc;
            if (keyType) { // Pairwise
                if (keyAck && !keyMic) {
                    msgNr = 1;
                    msgDesc = "Message 1 of 4";
                } else if (!keyAck && keyMic && !secure) {
                    msgNr = 2;
                    msgDesc = "Message 2 of 4";
                } else if (keyAck && keyMic && install) {
                    msgNr = 3;
                    msgDesc = "Message 3 of 4";
                } else if (!keyAck && keyMic && !install) {
                    msgNr = 4;
                    msgDesc = "Message 4 of 4";
                } else {
                    msgDesc = "Pairwise Key";
                }
            } else { // Group
                if (keyAck && keyMic) {
                    msgNr = 1;
                    msgDesc = "Group Message 1 of 2";
                } else if (!keyAck && keyMic) {
                    msgNr = 2;
                    msgDesc = "Group Message 2 of 2";
                } else {
                    msgDesc = "Group Key";
                }
            }

            ctx.pack.app_flags = msgNr; // eapol.keydes.msgnr

            const std::string descShort = (descType == 2 ? "RSN" : "WPA");
            ctx.pack.info = "Key (" + descShort + ") - " + msgDesc;

            if (eapolLayer) {
                Field &keyTree = eapolLayer->add(std::string(keyDescriptorTypeName(descType)), baseOffset + 4, actualSpan - 4);
                keyTree.add("Descriptor Type: " + std::string(keyDescriptorTypeName(descType)) + " (" + std::to_string(descType) + ")", baseOffset + 4, 1);

                Field &infoTree = keyTree.add("Key Information: " + hexString(keyInfo, 4), baseOffset + 5, 2);
                infoTree.add("Key Descriptor Version: " + std::to_string(keyDescVer), baseOffset + 5, 2);
                infoTree.add("Key Type: " + std::string(keyType ? "Pairwise" : "Group") + " Key", baseOffset + 5, 2);
                infoTree.add("Key Index: " + std::to_string(keyIndex), baseOffset + 5, 2);
                infoTree.add("Install: " + std::string(install ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Key ACK: " + std::string(keyAck ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Key MIC: " + std::string(keyMic ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Secure: " + std::string(secure ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Error: " + std::string(error ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Request: " + std::string(request ? "Set" : "Not set"), baseOffset + 5, 2);
                infoTree.add("Encrypted Key Data: " + std::string(encrypted ? "Set" : "Not set"), baseOffset + 5, 2);
                if (smk) infoTree.add("SMK Message: Set", baseOffset + 5, 2);

                keyTree.add("Key Length: " + std::to_string(keyLen), baseOffset + 7, 2);
                keyTree.add("Replay Counter: " + std::to_string(replay), baseOffset + 9, 8);
                keyTree.add("WPA Key Nonce: " + bytesToHex(nonce, 32), baseOffset + 17, 32);
                keyTree.add("Key IV: " + bytesToHex(iv, 16), baseOffset + 49, 16);
                keyTree.add("Key RSC: " + bytesToHex(rsc, 8), baseOffset + 65, 8);
                keyTree.add("Key ID: " + bytesToHex(id, 8), baseOffset + 73, 8);
                keyTree.add("Key MIC: " + bytesToHex(mic, 16), baseOffset + 81, 16);
                keyTree.add("Key Data Length: " + std::to_string(keyDataLen), baseOffset + 97, 2);

                if (keyDataLen > 0 && length >= 99 + keyDataLen) {
                    Field &dataTree = keyTree.add("Key Data (" + std::to_string(keyDataLen) + " bytes)", baseOffset + 99, keyDataLen);
                    if (encrypted) {
                        dataTree.add("Encrypted Data: " + bytesToHex(k + 95, keyDataLen), baseOffset + 99, keyDataLen);
                    } else {
                        // Parse unencrypted KDEs or RSN IEs
                        size_t doff = 0;
                        while (doff + 2 <= keyDataLen) {
                            const uint8_t elemType = static_cast<uint8_t>(k[95 + doff]);
                            const uint8_t elemLen = static_cast<uint8_t>(k[95 + doff + 1]);
                            if (doff + 2 + elemLen > keyDataLen) break;

                            const char *elemData = k + 95 + doff + 2;
                            if (elemType == 0xDD && elemLen >= 4) { // Vendor Specific KDE
                                const uint8_t kdeType = static_cast<uint8_t>(elemData[3]);
                                std::string kdeName;
                                switch (kdeType) {
                                    case 1: kdeName = "GTK"; break;
                                    case 2: kdeName = "STAKey MAC"; break;
                                    case 3: kdeName = "PMKID"; break;
                                    case 4: kdeName = "IGTK"; break;
                                    case 5: kdeName = "BIGTK"; break;
                                    default: kdeName = "Type " + std::to_string(kdeType); break;
                                }
                                Field &kdeTree = dataTree.add("KDE: " + kdeName + " (" + std::to_string(elemLen) + " bytes)",
                                                              baseOffset + 99 + doff, 2 + elemLen);
                                kdeTree.add("OUI: 00:0f:ac", baseOffset + 99 + doff + 2, 3);
                                kdeTree.add("Data Type: " + kdeName + " (" + std::to_string(kdeType) + ")", baseOffset + 99 + doff + 5, 1);
                                if (elemLen > 4) {
                                    kdeTree.add("Data: " + bytesToHex(elemData + 4, elemLen - 4), baseOffset + 99 + doff + 6, elemLen - 4);
                                }
                            } else if (elemType == 0x30) { // RSN IE
                                dataTree.add("RSN IE (" + std::to_string(elemLen) + " bytes)",
                                             baseOffset + 99 + doff, 2 + elemLen);
                            }
                            doff += 2 + elemLen;
                        }
                    }
                }
            }
            return;
        } else {
            ctx.pack.info = "Key (" + std::string(keyDescriptorTypeName(descType)) + ")";
            if (eapolLayer) {
                eapolLayer->add("Descriptor Type: " + std::string(keyDescriptorTypeName(descType)) + " (" + std::to_string(descType) + ")", baseOffset + 4, 1);
            }
            return;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // EAP Packet (Type 0)
    // ---------------------------------------------------------------------------------------------
    if (type == 0) {
        if (length < 8) {
            ctx.markMalformed("truncated EAP header");
            return;
        }

        const char *eap = data + 4;
        const uint8_t code = static_cast<uint8_t>(eap[0]);
        const uint8_t id = static_cast<uint8_t>(eap[1]);
        const uint16_t eapLen = be16(eap + 2);

        ctx.pack.app_code = code; // eap.code

        uint8_t eapType = 0;
        std::string idText;
        if ((code == 1 || code == 2) && length >= 9) { // Request or Response
            eapType = static_cast<uint8_t>(eap[4]);
            ctx.pack.app_flags = eapType; // eap.type

            if (eapType == 1 && eapLen > 5 && length >= 9) { // Identity
                const size_t textLen = std::min<size_t>(eapLen - 5, length - 9);
                idText = std::string(eap + 5, textLen);
                ctx.pack.app_text = idText;
            }
        }

        // Info column
        std::string info;
        if (code == 1 || code == 2) {
            info = std::string(eapCodeName(code)) + ", " + eapTypeName(eapType);
            if (!idText.empty()) info += ": " + idText;
        } else if (code == 3) {
            info = "Success";
        } else if (code == 4) {
            info = "Failure";
        } else {
            info = "Code " + std::to_string(code);
        }
        ctx.pack.info = info;

        if (eapolLayer) {
            const size_t eapActual = std::min(length - 4, static_cast<size_t>(eapLen));
            Field &eapTree = eapolLayer->add("Extensible Authentication Protocol", baseOffset + 4, eapActual);
            eapTree.add("Code: " + std::string(eapCodeName(code)) + " (" + std::to_string(code) + ")", baseOffset + 4, 1);
            eapTree.add("Id: " + std::to_string(id), baseOffset + 5, 1);
            eapTree.add("Length: " + std::to_string(eapLen), baseOffset + 6, 2);

            if (code == 1 || code == 2) {
                eapTree.add("Type: " + std::string(eapTypeName(eapType)) + " (" + std::to_string(eapType) + ")", baseOffset + 8, 1);
                if (eapType == 1 && !idText.empty()) {
                    eapTree.add("Identity: " + idText, baseOffset + 9, idText.size());
                } else if (eapActual > 5) {
                    eapTree.add("Type-Data: " + bytesToHex(eap + 5, eapActual - 5), baseOffset + 9, eapActual - 5);
                }
            }
        }
        return;
    }

    ctx.pack.info = std::string(eapolTypeName(type));
}

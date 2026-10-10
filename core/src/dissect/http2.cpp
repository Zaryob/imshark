#include "protocols.h"

#include <algorithm>

#include "hpack.h"
#include "reader.h"
#include "util.h"

#include <cstring>
#include <string>
#include <vector>

namespace dissect {

namespace {

const char *http2FrameTypeName(uint8_t type) {
    switch (type) {
        case 0: return "DATA";
        case 1: return "HEADERS";
        case 2: return "PRIORITY";
        case 3: return "RST_STREAM";
        case 4: return "SETTINGS";
        case 5: return "PUSH_PROMISE";
        case 6: return "PING";
        case 7: return "GOAWAY";
        case 8: return "WINDOW_UPDATE";
        case 9: return "CONTINUATION";
        default: return "UNKNOWN";
    }
}

const char *http2ErrorName(uint32_t code) {
    switch (code) {
        case 0x0: return "NO_ERROR (0x0)";
        case 0x1: return "PROTOCOL_ERROR (0x1)";
        case 0x2: return "INTERNAL_ERROR (0x2)";
        case 0x3: return "FLOW_CONTROL_ERROR (0x3)";
        case 0x4: return "SETTINGS_TIMEOUT (0x4)";
        case 0x5: return "STREAM_CLOSED (0x5)";
        case 0x6: return "FRAME_SIZE_ERROR (0x6)";
        case 0x7: return "REFUSED_STREAM (0x7)";
        case 0x8: return "CANCEL (0x8)";
        case 0x9: return "COMPRESSION_ERROR (0x9)";
        case 0xa: return "CONNECT_ERROR (0xa)";
        case 0xb: return "ENHANCE_YOUR_CALM (0xb)";
        case 0xc: return "INADEQUATE_SECURITY (0xc)";
        case 0xd: return "HTTP_1_1_REQUIRED (0xd)";
        default: return "UNKNOWN_ERROR";
    }
}

const char *http2SettingsName(uint16_t id) {
    switch (id) {
        case 1: return "SETTINGS_HEADER_TABLE_SIZE";
        case 2: return "SETTINGS_ENABLE_PUSH";
        case 3: return "SETTINGS_MAX_CONCURRENT_STREAMS";
        case 4: return "SETTINGS_INITIAL_WINDOW_SIZE";
        case 5: return "SETTINGS_MAX_FRAME_SIZE";
        case 6: return "SETTINGS_MAX_HEADER_LIST_SIZE";
        default: return "SETTINGS_UNKNOWN";
    }
}

constexpr const char *kClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t kPrefaceLen = 24;

} // namespace

StreamFrame frameHttp2(const char *data, size_t length) {
    if (length == 0) return {StreamFrame::Kind::NeedMore, 9};

    if (data[0] == 'P') {
        const size_t checkLen = std::min(length, kPrefaceLen);
        if (std::memcmp(data, kClientPreface, checkLen) != 0) {
            return {StreamFrame::Kind::Reject, 0};
        }
        if (length < kPrefaceLen) {
            return {StreamFrame::Kind::NeedMore, kPrefaceLen - length};
        }
        return {StreamFrame::Kind::Complete, kPrefaceLen};
    }

    // Not preface: must be an HTTP/2 frame header
    // Byte 0 of length must be <= 0x0f (frame size <= 1MB)
    if (static_cast<uint8_t>(data[0]) > 0x0f) {
        return {StreamFrame::Kind::Reject, 0};
    }

    if (length >= 4) {
        const uint8_t type = static_cast<uint8_t>(data[3]);
        if (type > 0x09) return {StreamFrame::Kind::Reject, 0};
    }

    if (length >= 5) {
        const uint8_t type = static_cast<uint8_t>(data[3]);
        const uint8_t flags = static_cast<uint8_t>(data[4]);
        if (type == 0 && (flags & ~0x09) != 0) return {StreamFrame::Kind::Reject, 0};
        if (type == 1 && (flags & ~0x2d) != 0) return {StreamFrame::Kind::Reject, 0};
        if ((type == 2 || type == 3 || type == 7 || type == 8) && flags != 0) return {StreamFrame::Kind::Reject, 0};
        if ((type == 4 || type == 6) && flags > 1) return {StreamFrame::Kind::Reject, 0};
        if (type == 5 && (flags & ~0x0c) != 0) return {StreamFrame::Kind::Reject, 0};
        if (type == 9 && (flags & ~0x04) != 0) return {StreamFrame::Kind::Reject, 0};
    }

    if (length < 9) {
        return {StreamFrame::Kind::NeedMore, 9 - length};
    }

    const uint32_t payloadLen = (static_cast<uint8_t>(data[0]) << 16) |
                                (static_cast<uint8_t>(data[1]) << 8) |
                                static_cast<uint8_t>(data[2]);
    const uint8_t type = static_cast<uint8_t>(data[3]);
    const uint32_t streamId = be32(data + 5) & 0x7FFFFFFF;

    if (payloadLen > 16777215) return {StreamFrame::Kind::Reject, 0};

    if (type == 0) { // DATA
        if (streamId == 0) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 1) { // HEADERS
        if (streamId == 0) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 4) { // SETTINGS
        if (streamId != 0 || (payloadLen % 6) != 0) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 6) { // PING
        if (streamId != 0 || payloadLen != 8) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 3) { // RST_STREAM
        if (streamId == 0 || payloadLen != 4) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 2) { // PRIORITY
        if (streamId == 0 || payloadLen != 5) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 8) { // WINDOW_UPDATE
        if (payloadLen != 4) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 7) { // GOAWAY
        if (streamId != 0 || payloadLen < 8) return {StreamFrame::Kind::Reject, 0};
    } else if (type == 9) { // CONTINUATION
        if (streamId == 0) return {StreamFrame::Kind::Reject, 0};
    }

    const size_t totalLen = 9 + payloadLen;
    if (length < totalLen) {
        return {StreamFrame::Kind::NeedMore, totalLen - length};
    }
    return {StreamFrame::Kind::Complete, totalLen};
}

bool dissectHttp2Heuristic(Context &ctx, const char *data, size_t length) {
    if (length >= 4 && std::memcmp(data, "PRI ", 4) == 0) {
        if (length < kPrefaceLen) return false;
        if (std::memcmp(data, kClientPreface, kPrefaceLen) == 0) {
            dissectHttp2(ctx, data, length);
            return true;
        }
    }
    return false;
}

void dissectHttp2(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "HTTP2";
    if (length == 0) return;

    packet::Field *layer = nullptr;
    const size_t baseOffset = ctx.offsetOf(data);
    if (ctx.wantFields()) {
        layer = &ctx.addLayer("Hypertext Transfer Protocol 2 (HTTP/2)", baseOffset, length);
    }

    size_t offset = 0;
    std::vector<std::string> summaries;
    bool hasFirstFrame = false;

    // Check for Connection Preface
    if (length >= kPrefaceLen && std::memcmp(data, kClientPreface, kPrefaceLen) == 0) {
        summaries.push_back("Magic: Connection Preface");
        if (layer) {
            packet::Field &pref = layer->add("Connection Preface: PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n", baseOffset, kPrefaceLen);
            pref.add("Stream Identifier: 0 (Connection)", baseOffset, kPrefaceLen);
        }
        if (!hasFirstFrame) {
            ctx.pack.app_type = 254; // Magic preface marker
            hasFirstFrame = true;
        }
        offset += kPrefaceLen;
    }

    HpackContext hpack;

    while (offset + 9 <= length) {
        const uint32_t payloadLen = (static_cast<uint8_t>(data[offset]) << 16) |
                                    (static_cast<uint8_t>(data[offset + 1]) << 8) |
                                    static_cast<uint8_t>(data[offset + 2]);
        const uint8_t frameType = static_cast<uint8_t>(data[offset + 3]);
        const uint8_t flags = static_cast<uint8_t>(data[offset + 4]);
        const uint32_t streamId = be32(data + offset + 5) & 0x7FFFFFFF;
        const size_t totalFrameBytes = 9 + payloadLen;

        if (offset + totalFrameBytes > length) {
            // Truncated frame
            const size_t rem = length - offset;
            if (layer) {
                layer->add("Truncated HTTP/2 Frame (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
            }
            summaries.push_back("Truncated Frame");
            break;
        }

        const char *payload = data + offset + 9;
        const size_t frameBase = baseOffset + offset;

        if (!hasFirstFrame) {
            ctx.pack.app_type = frameType;
            ctx.pack.app_flags = flags;
            ctx.pack.app_stream = streamId;
            hasFirstFrame = true;
        }

        packet::Field *frameNode = nullptr;
        if (layer) {
            std::string frameTitle = std::string(http2FrameTypeName(frameType)) + " (Type " +
                                     std::to_string(frameType) + "), Stream: " + std::to_string(streamId) +
                                     ", Length: " + std::to_string(payloadLen);
            frameNode = &layer->add(frameTitle, frameBase, totalFrameBytes);
            frameNode->add("Length: " + std::to_string(payloadLen), frameBase, 3);
            frameNode->add("Type: " + std::string(http2FrameTypeName(frameType)) + " (" + std::to_string(frameType) + ")", frameBase + 3, 1);
            frameNode->add("Flags: " + hexString(flags, 2), frameBase + 4, 1);
            frameNode->add("Stream Identifier: " + std::to_string(streamId), frameBase + 5, 4);
        }

        switch (frameType) {
            case 0: { // DATA
                const bool endStream = (flags & 0x01) != 0;
                const bool padded = (flags & 0x08) != 0;
                uint8_t padLen = 0;
                size_t dataLen = payloadLen;
                if (padded && payloadLen > 0) {
                    padLen = static_cast<uint8_t>(payload[0]);
                    dataLen = (payloadLen >= 1u + padLen) ? payloadLen - 1u - padLen : 0;
                    if (frameNode) frameNode->add("Pad Length: " + std::to_string(padLen), frameBase + 9, 1);
                }
                std::string summary = "DATA[stream " + std::to_string(streamId) + "]: " + std::to_string(dataLen) + " bytes";
                if (endStream) summary += " (END_STREAM)";
                summaries.push_back(summary);

                if (frameNode) {
                    const size_t dataOffset = padded ? 10 : 9;
                    if (dataLen > 0) frameNode->add("Data (" + std::to_string(dataLen) + " bytes)", frameBase + dataOffset, dataLen);
                    // a Pad Length larger than what the payload holds (damaged frame) shows only the bytes that exist
                    const size_t padShown = std::min<size_t>(padLen, payloadLen >= 1 + dataLen ? payloadLen - 1 - dataLen : 0);
                    if (padShown > 0) frameNode->add("Padding (" + std::to_string(padLen) + " bytes)", frameBase + dataOffset + dataLen, padShown);
                }
                break;
            }
            case 1: { // HEADERS
                const bool endStream = (flags & 0x01) != 0;
                const bool endHeaders = (flags & 0x04) != 0;
                const bool padded = (flags & 0x08) != 0;
                const bool priority = (flags & 0x20) != 0;

                size_t hOffset = 0;
                uint8_t padLen = 0;
                if (padded && payloadLen > 0) {
                    padLen = static_cast<uint8_t>(payload[0]);
                    hOffset += 1;
                    if (frameNode) frameNode->add("Pad Length: " + std::to_string(padLen), frameBase + 9, 1);
                }
                if (priority && payloadLen >= hOffset + 5) {
                    const bool exclusive = (static_cast<uint8_t>(payload[hOffset]) & 0x80) != 0;
                    const uint32_t dep = be32(payload + hOffset) & 0x7FFFFFFF;
                    const uint8_t weight = static_cast<uint8_t>(payload[hOffset + 4]);
                    if (frameNode) {
                        frameNode->add("Stream Dependency: " + std::to_string(dep) + (exclusive ? " (Exclusive)" : ""), frameBase + 9 + hOffset, 4);
                        frameNode->add("Weight: " + std::to_string(weight), frameBase + 9 + hOffset + 4, 1);
                    }
                    hOffset += 5;
                }

                const size_t blockLen = (payloadLen >= hOffset + padLen) ? (payloadLen - hOffset - padLen) : 0;
                std::vector<HeaderField> headers;
                if (blockLen > 0) {
                    hpack.decode(payload + hOffset, blockLen, headers);
                }

                std::string method, path, status, authority;
                for (const auto &hf : headers) {
                    if (hf.name == ":method") method = hf.value;
                    else if (hf.name == ":path") path = hf.value;
                    else if (hf.name == ":status") status = hf.value;
                    else if (hf.name == ":authority") authority = hf.value;
                }

                std::string summary = "HEADERS[stream " + std::to_string(streamId) + "]: ";
                if (!method.empty()) {
                    summary += method + " " + path;
                    if (ctx.pack.app_text.empty()) ctx.pack.app_text = method;
                    if (ctx.pack.app_text2.empty()) ctx.pack.app_text2 = path;
                } else if (!status.empty()) {
                    summary += status;
                    if (ctx.pack.app_code == 0) {
                        try { ctx.pack.app_code = static_cast<uint32_t>(std::stoul(status)); } catch (...) {}
                    }
                } else {
                    summary += std::to_string(headers.size()) + " headers";
                }
                if (endStream) summary += " (END_STREAM)";
                if (endHeaders) summary += " (END_HEADERS)";
                summaries.push_back(summary);

                if (frameNode) {
                    if (frameNode && !headers.empty()) {
                        packet::Field &hdrBlock = frameNode->add("Header Block (" + std::to_string(headers.size()) + " headers)",
                                                                 frameBase + 9 + hOffset, blockLen);
                        for (const auto &hf : headers) {
                            hdrBlock.add(hf.name + ": " + hf.value, frameBase + 9 + hOffset, blockLen);
                        }
                    }
                }
                break;
            }
            case 2: { // PRIORITY
                if (payloadLen >= 5 && frameNode) {
                    const bool exclusive = (static_cast<uint8_t>(payload[0]) & 0x80) != 0;
                    const uint32_t dep = be32(payload) & 0x7FFFFFFF;
                    const uint8_t weight = static_cast<uint8_t>(payload[4]);
                    frameNode->add("Stream Dependency: " + std::to_string(dep) + (exclusive ? " (Exclusive)" : ""), frameBase + 9, 4);
                    frameNode->add("Weight: " + std::to_string(weight), frameBase + 13, 1);
                }
                summaries.push_back("PRIORITY[stream " + std::to_string(streamId) + "]");
                break;
            }
            case 3: { // RST_STREAM
                uint32_t errCode = (payloadLen >= 4) ? be32(payload) : 0;
                summaries.push_back("RST_STREAM[stream " + std::to_string(streamId) + "]: " + http2ErrorName(errCode));
                if (frameNode && payloadLen >= 4) {
                    frameNode->add("Error Code: " + std::string(http2ErrorName(errCode)), frameBase + 9, 4);
                }
                break;
            }
            case 4: { // SETTINGS
                const bool ack = (flags & 0x01) != 0;
                if (ack) {
                    summaries.push_back("SETTINGS: ACK");
                } else {
                    const size_t numSettings = payloadLen / 6;
                    summaries.push_back("SETTINGS: " + std::to_string(numSettings) + " parameter(s)");
                    if (frameNode) {
                        for (size_t s = 0; s + 6 <= payloadLen; s += 6) {
                            const uint16_t id = be16(payload + s);
                            const uint32_t val = be32(payload + s + 2);
                            frameNode->add(std::string(http2SettingsName(id)) + ": " + std::to_string(val), frameBase + 9 + s, 6);
                        }
                    }
                }
                break;
            }
            case 5: { // PUSH_PROMISE
                if (payloadLen >= 4) {
                    const uint32_t promisedId = be32(payload) & 0x7FFFFFFF;
                    summaries.push_back("PUSH_PROMISE[stream " + std::to_string(streamId) + "]: promised stream " + std::to_string(promisedId));
                    if (frameNode) frameNode->add("Promised Stream: " + std::to_string(promisedId), frameBase + 9, 4);
                } else {
                    summaries.push_back("PUSH_PROMISE[stream " + std::to_string(streamId) + "]");
                }
                break;
            }
            case 6: { // PING
                const bool ack = (flags & 0x01) != 0;
                summaries.push_back(std::string("PING: ") + (ack ? "ACK" : "Request"));
                if (frameNode && payloadLen >= 8) {
                    frameNode->add("Data: " + hexString(be32(payload), 8) + hexString(be32(payload + 4), 8), frameBase + 9, 8);
                }
                break;
            }
            case 7: { // GOAWAY
                if (payloadLen >= 8) {
                    const uint32_t lastId = be32(payload) & 0x7FFFFFFF;
                    const uint32_t errCode = be32(payload + 4);
                    summaries.push_back("GOAWAY: Last Stream " + std::to_string(lastId) + ", " + http2ErrorName(errCode));
                    if (frameNode) {
                        frameNode->add("Last Stream Identifier: " + std::to_string(lastId), frameBase + 9, 4);
                        frameNode->add("Error Code: " + std::string(http2ErrorName(errCode)), frameBase + 13, 4);
                    }
                } else {
                    summaries.push_back("GOAWAY");
                }
                break;
            }
            case 8: { // WINDOW_UPDATE
                if (payloadLen >= 4) {
                    const uint32_t inc = be32(payload) & 0x7FFFFFFF;
                    summaries.push_back("WINDOW_UPDATE[stream " + std::to_string(streamId) + "]: " + std::to_string(inc));
                    if (frameNode) frameNode->add("Window Size Increment: " + std::to_string(inc), frameBase + 9, 4);
                } else {
                    summaries.push_back("WINDOW_UPDATE[stream " + std::to_string(streamId) + "]");
                }
                break;
            }
            case 9: { // CONTINUATION
                summaries.push_back("CONTINUATION[stream " + std::to_string(streamId) + "]: " + std::to_string(payloadLen) + " bytes");
                break;
            }
            default: {
                summaries.push_back(std::string(http2FrameTypeName(frameType)) + "[stream " + std::to_string(streamId) + "]");
                break;
            }
        }

        offset += totalFrameBytes;
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
        ctx.pack.info = "HTTP/2 payload (" + std::to_string(length) + " bytes)";
    }
}

} // namespace dissect

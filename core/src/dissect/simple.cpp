// Application protocols that are only summarised for now: SNMP, Telnet, SMTP and BGP.
#include "protocols.h"

#include "util.h"

namespace {
    using namespace dissect;

    // Adds a layer that only shows its payload as raw data
    void addDataLayer(Context &ctx, const std::string &name, const char *payload, size_t length) {
        if (!ctx.wantFields()) return;
        const size_t o = ctx.offsetOf(payload);
        packet::Field &l = ctx.addLayer(name, o, length);
        if (length > 0) l.add("Data (" + std::to_string(length) + " bytes): " + asciiPreview(payload, length), o, length);
    }
} // namespace


void dissect::dissectTelnet(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "Telnet";
    ctx.pack.info += "[ Telnet data: " + std::string(data, std::min<size_t>(length, 50)) + (length > 50 ? "..." : "") + " ]";
    addDataLayer(ctx, "Telnet", data, length);
}

void dissect::dissectSmtp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "SMTP";
    ctx.pack.info = "SMTP data: " + std::string(data, std::min<size_t>(length, 50)) + (length > 50 ? "..." : "");
    addDataLayer(ctx, "Simple Mail Transfer Protocol", data, length);
}

void dissect::dissectBgp(Context &ctx, const char *data, size_t length) {
    ctx.pack.protocol = "BGP";
    if (length < 19) {
        ctx.pack.info += " [ BGP: truncated ]";
    } else {
        // The message type is the 19th byte (after 16 marker + 2 length bytes).
        std::string type;
        switch (static_cast<uint8_t>(data[18])) {
            case 1: type = "OPEN"; break;
            case 2: type = "UPDATE"; break;
            case 3: type = "NOTIFICATION"; break;
            case 4: type = "KEEPALIVE"; break;
            default: type = "Unknown";
        }
        ctx.pack.info += " [ BGP: " + type + " ]";
    }
    addDataLayer(ctx, "Border Gateway Protocol", data, length);
}

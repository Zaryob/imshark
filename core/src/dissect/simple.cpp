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


#include "ipip.h"
#include "protocols.h"
#include "util.h"

namespace dissect {
    void dissectIpInIp(Context &ctx, const char *data, size_t length) {
        ctx.pack.has_ipip = 1;
        if (length < 1) {
            ctx.markMalformed("IP-in-IP payload truncated");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "IP-in-IP";
            return;
        }
        const uint8_t version = static_cast<uint8_t>(data[0]) >> 4;
        if (version == 4) {
            dissectIPv4(ctx, data, length);
        } else if (version == 6) {
            dissectIPv6(ctx, data, length);
        } else {
            ctx.markMalformed("IP-in-IP inner payload is not an IP packet");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "IP-in-IP";
        }
    }
} // namespace dissect

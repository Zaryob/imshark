// Filter fields of HTTP/2 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerHttp2Fields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"http2", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(1); }, "HTTP/2"},
            {"http2.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_type); }, "HTTP/2 frame type (0 = DATA, 1 = HEADERS, 4 = SETTINGS ...)"},
            {"http2.streamid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_stream); }, "HTTP/2 stream identifier"},
            {"http2.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_flags); }, "HTTP/2 frame flags"},
            {"http2.headers.method", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && !p.app_text.empty()) o.addS(p.app_text); }, "HTTP/2 request method"},
            {"http2.headers.path", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && !p.app_text2.empty()) o.addS(p.app_text2); }, "HTTP/2 request path"},
            {"http2.headers.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && p.app_code != 0) o.addU(p.app_code); }, "HTTP/2 response status code"},
        });
    }
} // namespace filter

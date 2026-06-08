// Filter fields of HTTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerHttpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"http", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(1); }, "HTTP/1.x"},
            {"http.request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(p.app_flags == 0); }, "HTTP request"},
            {"http.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(p.app_flags == 1); }, "HTTP response"},
            {"http.request.method", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 0) o.addS(httpMethodName(p.app_type)); }, "HTTP request method (GET, POST ...)"},
            {"http.request.uri", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 0) o.addS(p.app_text2); }, "HTTP request URI"},
            {"http.host", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && !p.app_text.empty()) o.addS(p.app_text); }, "HTTP Host header"},
            {"http.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 1) o.addU(p.app_code); }, "HTTP response status code"},
            {"http.content_type", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 1 && !p.app_text2.empty()) o.addS(p.app_text2); }, "HTTP response Content-Type"},
        });
    }
} // namespace filter

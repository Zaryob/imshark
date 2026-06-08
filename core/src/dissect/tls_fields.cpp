// Filter fields of TLS (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerTlsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"tls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") || dissect::hasTlsSummary(p)) o.addU(1); }, "TLS / SSL (also HTTP packets that were decrypted from TLS)"},
            {"tls.decrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") || dissect::hasTlsSummary(p)) o.addU(dissect::tlsSummaryState(p) == dissect::TlsRecordState::Decrypted); }, "The packet carries TLS records that were decrypted with a key log"},
            {"tls.decryption_status", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (dissect::hasTlsSummary(p)) o.addS(dissect::tlsStateName(dissect::tlsSummaryState(p))); }, "What became of the protected TLS records of the packet: decrypted, tag_failure (wrong key), no_key, unsupported_suite, malformed, unavailable (no OpenSSL), capture_gap, no_handshake, early_data, state_lost"},
            {"tls.record.content_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_code); }, "Content type of the first TLS record (22 = handshake, 23 = application data)"},
            {"tls.record.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_flags); }, "Version of the first TLS record (0x0303 = TLS 1.2)"},
            {"tls.handshake.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && p.app_type != 0) o.addU(p.app_type); }, "First handshake message type (1 = ClientHello, 2 = ServerHello ...)"},
            {"tls.handshake.certificate_subject", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && !p.app_text2.empty()) o.addS(p.app_text2); }, "Common name of the first certificate in a Certificate message"},
            {"tls.handshake.extensions_server_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && !p.app_text.empty()) o.addS(p.app_text); }, "Server name indication (SNI) of a ClientHello"},
        });
    }
} // namespace filter

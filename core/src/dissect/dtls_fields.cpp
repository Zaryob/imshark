// Filter fields of DTLS (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerDtlsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dtls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS")) o.addU(1); }, "Datagram TLS (DTLS)"},
            {"dtls.decrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS")) o.addU(dissect::dtlsSummaryState(p) == dissect::TlsRecordState::Decrypted); }, "The packet carries DTLS records that were decrypted with a key log"},
            {"dtls.decryption_status", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (dissect::hasDtlsSummary(p)) o.addS(dissect::tlsStateName(dissect::dtlsSummaryState(p))); }, "What became of the protected DTLS records of the packet: decrypted, tag_failure (wrong key), no_key, unsupported_suite, malformed, unavailable (no OpenSSL), no_handshake, state_lost"},
            {"dtls.record.content_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && (p.app_code & 0x1f) != 0) o.addU(p.app_code & 0x1f); }, "Content type of the first DTLS record (22 = handshake, 23 = application data)"},
            {"dtls.record.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && p.app_flags != 0) o.addU(p.app_flags); }, "Version of the first DTLS record (0xfefd = DTLS 1.2, 0xfeff = 1.0; 0xfefc for a DTLS 1.3 unified header)"},
            {"dtls.record.epoch", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && (p.app_code & 0x1f) != 0) o.addU(p.tcp_pdu_len >> 16); }, "Epoch of the first DTLS record"},
            {"dtls.record.sequence_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && (p.app_code & 0x1f) != 0) o.addU((static_cast<uint64_t>(p.tcp_pdu_len & 0xffff) << 32) | p.tcp_pdu_start); }, "48 bit sequence number of the first DTLS record"},
            {"dtls.handshake.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && p.app_type != 0) o.addU(p.app_type); }, "First handshake message type (1 = ClientHello, 2 = ServerHello, 3 = HelloVerifyRequest ...)"},
            {"dtls.handshake.cookie_length", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && (p.app_code >> 5) != 0) o.addU((p.app_code >> 5) - 1); }, "Length of the cookie of a ClientHello or HelloVerifyRequest"},
            {"dtls.handshake.certificate_subject", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && !p.app_text2.empty()) o.addS(p.app_text2); }, "Common name of the first certificate in a Certificate message"},
            {"dtls.handshake.extensions_server_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DTLS") && !p.app_text.empty()) o.addS(p.app_text); }, "Server name indication (SNI) of a ClientHello"},
        });
    }
} // namespace filter

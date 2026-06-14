// Filter fields of SNMP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSnmpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"snmp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(1); }, "SNMP"},
            {"snmp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_flags); }, "SNMP version (0 = v1, 1 = v2c, 3 = v3)"},
            {"snmp.community", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text.empty()) o.addS(p.app_text); }, "SNMP community string or v3 user name"},
            {"snmp.pdu_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_type); }, "SNMP PDU type (0 = GetRequest, 1 = GetNextRequest, 2 = Response ...)"},
            {"snmp.request_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.tcp_pdu_start); }, "SNMP request ID"},
            {"snmp.error_status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_code); }, "SNMP error-status code"},
            {"snmp.oid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SNMP first variable binding OID"},
        });
    }
} // namespace filter

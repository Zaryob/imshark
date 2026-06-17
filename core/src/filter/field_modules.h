#pragma once

// The per-protocol filter field modules. Each is defined in core/src/dissect/<protocol>_fields.cpp, next to the
// dissector whose summary facts its extractors read, and adds that protocol's fields to the registry.

#include <filter/fields.h>

namespace filter {
    /// Registers every module below, in one explicit list (see field_modules.cpp). The only caller is the code that
    /// builds the built-in table; tests may call it on a registry of their own.
    void registerBuiltinFields(FieldRegistry &registry);

    // One module per protocol (defined in core/src/dissect/<name>_fields.cpp)
    void registerFrameFields(FieldRegistry &registry);
    void registerEthernetFields(FieldRegistry &registry);
    void registerArpFields(FieldRegistry &registry);
    void registerIpFields(FieldRegistry &registry);
    void registerIcmpFields(FieldRegistry &registry);
    void registerIgmpFields(FieldRegistry &registry);
    void registerTcpFields(FieldRegistry &registry);
    void registerUdpFields(FieldRegistry &registry);
    void registerSctpFields(FieldRegistry &registry);
    void registerTlsFields(FieldRegistry &registry);
    void registerDtlsFields(FieldRegistry &registry);
    void registerHttpFields(FieldRegistry &registry);
    void registerHttp2Fields(FieldRegistry &registry);
    void registerIndustrialFields(FieldRegistry &registry);
    void registerOspfFields(FieldRegistry &registry);
    void registerIpsecFields(FieldRegistry &registry);
    void registerLdapFields(FieldRegistry &registry);
    void registerKerberosFields(FieldRegistry &registry);
    void registerPostgresFields(FieldRegistry &registry);
    void registerMysqlFields(FieldRegistry &registry);
    void registerTdsFields(FieldRegistry &registry);
    void registerSmb2Fields(FieldRegistry &registry);
    void registerDcerpcFields(FieldRegistry &registry);
    void registerNfsFields(FieldRegistry &registry);
    void registerDhcpFields(FieldRegistry &registry);
    void registerNtpFields(FieldRegistry &registry);
    void registerDnsFields(FieldRegistry &registry);
    void registerSnmpFields(FieldRegistry &registry);
    void registerTelnetFields(FieldRegistry &registry);
    void registerSmtpFields(FieldRegistry &registry);
    void registerFtpFields(FieldRegistry &registry);
    void registerTftpFields(FieldRegistry &registry);
    void registerBgpFields(FieldRegistry &registry);
    void registerSshFields(FieldRegistry &registry);
    void registerWlanFields(FieldRegistry &registry);
    void registerRadiotapFields(FieldRegistry &registry);
    void registerPpiFields(FieldRegistry &registry);
    void registerEapolFields(FieldRegistry &registry);
    void registerLlcFields(FieldRegistry &registry);
    void registerStpFields(FieldRegistry &registry);
    void registerPppFields(FieldRegistry &registry);
    void registerPppoeFields(FieldRegistry &registry);
    void registerMplsFields(FieldRegistry &registry);
    void registerIpipFields(FieldRegistry &registry);
    void registerGreFields(FieldRegistry &registry);
    void registerLldpFields(FieldRegistry &registry);
    void registerSlowProtocolsFields(FieldRegistry &registry);
    void registerMacControlFields(FieldRegistry &registry);
    void registerBluetoothFields(FieldRegistry &registry);
    void registerUsbFields(FieldRegistry &registry);
} // namespace filter

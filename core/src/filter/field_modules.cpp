#include "field_modules.h"

// The explicit list of field modules. A new protocol adds its register...Fields() function here (and its source file to
// core/CMakeLists.txt); nothing is registered by static initialisers, so the table cannot depend on link or load order.
namespace filter {
    void registerBuiltinFields(FieldRegistry &registry) {
        registerFrameFields(registry);
        registerEthernetFields(registry);
        registerArpFields(registry);
        registerIpFields(registry);
        registerIcmpFields(registry);
        registerIgmpFields(registry);
        registerTcpFields(registry);
        registerUdpFields(registry);
        registerSctpFields(registry);
        registerTlsFields(registry);
        registerDtlsFields(registry);
        registerHttpFields(registry);
        registerHttp2Fields(registry);
        registerIndustrialFields(registry);
        registerOspfFields(registry);
        registerIpsecFields(registry);
        registerLdapFields(registry);
        registerKerberosFields(registry);
        registerPostgresFields(registry);
        registerMysqlFields(registry);
        registerTdsFields(registry);
        registerSmb2Fields(registry);
        registerDcerpcFields(registry);
        registerNfsFields(registry);
        registerDhcpFields(registry);
        registerNtpFields(registry);
        registerDnsFields(registry);
        registerSnmpFields(registry);
        registerTelnetFields(registry);
        registerSmtpFields(registry);
        registerFtpFields(registry);
        registerTftpFields(registry);
        registerBgpFields(registry);
        registerSshFields(registry);
        registerWlanFields(registry);
        registerRadiotapFields(registry);
        registerPpiFields(registry);
        registerEapolFields(registry);
        registerLlcFields(registry);
        registerStpFields(registry);
        registerPppFields(registry);
        registerPppoeFields(registry);
        registerMplsFields(registry);
        registerIpipFields(registry);
        registerGreFields(registry);
        registerLldpFields(registry);
        registerSlowProtocolsFields(registry);
        registerMacControlFields(registry);
        registerBluetoothFields(registry);
        registerUsbFields(registry);
    }
} // namespace filter

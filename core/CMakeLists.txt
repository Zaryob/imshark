# imshark_core: capture file readers, protocol parsing and the packet model.
# Deliberately free of any UI / OpenGL / GLFW dependency so it can be tested and reused on its own.
add_library(imshark_core STATIC
    src/capture/live_capture.cpp
    src/capture_reader.cpp
    src/core.cpp
    src/io/format_registry.cpp
    src/io/pcap_reader.cpp
    src/io/pcapng_reader.cpp
    src/io/snoop_reader.cpp
    src/io/netmon_reader.cpp
    src/io/erf_reader.cpp
    src/io/iptrace_reader.cpp
    src/gzip.cpp
    src/temp_file.cpp
    src/packet_parser.cpp
    src/tcp_connection.cpp
    src/network/ip_reassembly.cpp
    src/network/datagram_reassembly.cpp
    src/dissect/registry.cpp
    src/dissect/ip.cpp
    src/dissect/arp.cpp
    src/dissect/icmp.cpp
    src/dissect/igmp.cpp
    src/dissect/ospf.cpp
    src/dissect/ipsec.cpp
    src/dissect/esp_null.cpp
    src/dissect/ike_payloads.cpp
    src/dissect/tcp.cpp
    src/dissect/tcp_streams.cpp
    src/dissect/x509.cpp
    src/dissect/udp.cpp
    src/dissect/sctp.cpp
    src/dissect/sctp_chunks.cpp
    src/dissect/sctp_session.cpp
    src/dissect/smb2_session.cpp
    src/dissect/dns.cpp
    src/dissect/http.cpp
    src/dissect/ntp.cpp
    src/dissect/snmp.cpp
    src/dissect/ldap.cpp
    src/dissect/kerberos.cpp
    src/dissect/spnego.cpp
    src/dissect/smb2.cpp
    src/dissect/dcerpc.cpp
    src/dissect/dcerpc_session.cpp
    src/dissect/nfs.cpp
    src/dissect/nfs3.cpp
    src/dissect/nfs4.cpp
    src/dissect/rpc_programs.cpp
    src/dissect/onc_rpc_session.cpp
    src/dissect/db_session.cpp
    src/dissect/postgres.cpp
    src/dissect/mysql.cpp
    src/dissect/tds.cpp
    src/dissect/usb.cpp
    src/dissect/bluetooth.cpp
    src/dissect/voip.cpp
    src/dissect/industrial.cpp
    src/dissect/tls.cpp
    src/dissect/tls_handshake.cpp
    src/dissect/dtls.cpp
    src/dissect/dtls_session.cpp
    src/dissect/dtls_decrypt.cpp
    src/dissect/tls_decrypt.cpp
    src/dissect/dhcp.cpp
    src/dissect/bgp.cpp
    src/dissect/telnet.cpp
    src/dissect/smtp.cpp
    src/dissect/ftp.cpp
    src/dissect/tftp.cpp
    src/dissect/ssh.cpp
    src/dissect/hpack.cpp
    src/dissect/http2.cpp
    src/dissect/wlan.cpp
    src/dissect/radiotap.cpp
    src/dissect/ppi.cpp
    src/dissect/eapol.cpp
    src/dissect/llc.cpp
    src/dissect/stp.cpp
    src/dissect/ppp.cpp
    src/dissect/pppoe.cpp
    src/dissect/mpls.cpp
    src/dissect/ipip.cpp
    src/dissect/gre.cpp
    src/dissect/lldp.cpp
    src/dissect/slow_protocols.cpp
    src/dissect/mac_control.cpp
    src/export/export.cpp
    src/dissect/frame_fields.cpp
    src/dissect/ethernet_fields.cpp
    src/dissect/arp_fields.cpp
    src/dissect/ip_fields.cpp
    src/dissect/icmp_fields.cpp
    src/dissect/igmp_fields.cpp
    src/dissect/tcp_fields.cpp
    src/dissect/udp_fields.cpp
    src/dissect/sctp_fields.cpp
    src/dissect/tls_fields.cpp
    src/dissect/dtls_fields.cpp
    src/dissect/http_fields.cpp
    src/dissect/http2_fields.cpp
    src/dissect/industrial_fields.cpp
    src/dissect/ospf_fields.cpp
    src/dissect/ipsec_fields.cpp
    src/dissect/ldap_fields.cpp
    src/dissect/kerberos_fields.cpp
    src/dissect/postgres_fields.cpp
    src/dissect/mysql_fields.cpp
    src/dissect/tds_fields.cpp
    src/dissect/smb2_fields.cpp
    src/dissect/dcerpc_fields.cpp
    src/dissect/nfs_fields.cpp
    src/dissect/dhcp_fields.cpp
    src/dissect/ntp_fields.cpp
    src/dissect/dns_fields.cpp
    src/dissect/snmp_fields.cpp
    src/dissect/telnet_fields.cpp
    src/dissect/smtp_fields.cpp
    src/dissect/ftp_fields.cpp
    src/dissect/tftp_fields.cpp
    src/dissect/bgp_fields.cpp
    src/dissect/ssh_fields.cpp
    src/dissect/wlan_fields.cpp
    src/dissect/radiotap_fields.cpp
    src/dissect/ppi_fields.cpp
    src/dissect/eapol_fields.cpp
    src/dissect/llc_fields.cpp
    src/dissect/stp_fields.cpp
    src/dissect/ppp_fields.cpp
    src/dissect/pppoe_fields.cpp
    src/dissect/mpls_fields.cpp
    src/dissect/ipip_fields.cpp
    src/dissect/gre_fields.cpp
    src/dissect/lldp_fields.cpp
    src/dissect/slow_protocols_fields.cpp
    src/dissect/mac_control_fields.cpp
    src/dissect/bluetooth_fields.cpp
    src/dissect/usb_fields.cpp
    src/filter/fields.cpp
    src/filter/field_modules.cpp
    src/filter/filter.cpp
    src/stats/statistics.cpp
    src/stream/follow.cpp
    src/stream/follow_tls.cpp
    src/tls/crypto.cpp
    src/tls/keylog.cpp
    src/tls/record_decryptor.cpp
)
set_target_properties(imshark_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Missing enabled dependencies are configuration errors, never silently disabled features.
if(IMSHARK_LIVE_CAPTURE)
    if(WIN32)
        # Windows capture is an explicit opt-in: the SDK and installed Npcap driver are required.
        find_path(PCAP_INCLUDE_DIR pcap.h HINTS "${NPCAP_SDK_DIR}" "$ENV{NPCAP_SDK_DIR}" PATH_SUFFIXES Include REQUIRED)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(_pcap_lib_suffix Lib/x64)
        else()
            set(_pcap_lib_suffix Lib)
        endif()
        find_library(PCAP_LIBRARY NAMES wpcap HINTS "${NPCAP_SDK_DIR}" "$ENV{NPCAP_SDK_DIR}" PATH_SUFFIXES ${_pcap_lib_suffix} REQUIRED)
        target_include_directories(imshark_core PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(imshark_core PUBLIC ${PCAP_LIBRARY} ws2_32)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
        target_link_libraries(imshark_core PUBLIC PkgConfig::PCAP)
    endif()
    target_sources(imshark_core PRIVATE src/capture/live_capture_pcap.cpp)
    target_compile_definitions(imshark_core PUBLIC IMSHARK_HAVE_LIVE_CAPTURE=1)
    message(STATUS "Live capture: enabled")
else()
    target_sources(imshark_core PRIVATE src/capture/live_capture_stub.cpp)
    message(STATUS "Live capture: disabled")
endif()

if(IMSHARK_TLS_DECRYPT)
    find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
    target_link_libraries(imshark_core PRIVATE OpenSSL::Crypto)
    target_compile_definitions(imshark_core PUBLIC IMSHARK_HAVE_TLS_DECRYPT=1)
    message(STATUS "TLS/DTLS decryption: OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "TLS/DTLS decryption: disabled")
endif()

find_package(Threads REQUIRED)  # the capture thread
target_link_libraries(imshark_core PUBLIC Threads::Threads)

target_include_directories(imshark_core PUBLIC src)

if(MSVC)
    target_compile_options(imshark_core PRIVATE /W4)
else()
    target_compile_options(imshark_core PRIVATE -Wall -Wextra)
endif()

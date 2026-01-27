# imshark_core: capture file readers, protocol parsing and the packet model.
# Deliberately free of any UI / OpenGL / GLFW dependency so it can be tested and reused on its own.
add_library(imshark_core STATIC
    src/capture/live_capture.cpp
    src/capture_reader.cpp
    src/core.cpp
    src/gzip.cpp
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
    src/dissect/tcp.cpp
    src/dissect/tcp_streams.cpp
    src/dissect/x509.cpp
    src/dissect/udp.cpp
    src/dissect/sctp.cpp
    src/dissect/dns.cpp
    src/dissect/http.cpp
    src/dissect/ntp.cpp
    src/dissect/snmp.cpp
    src/dissect/ldap.cpp
    src/dissect/kerberos.cpp
    src/dissect/smb2.cpp
    src/dissect/dcerpc.cpp
    src/dissect/nfs.cpp
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
    src/filter/fields.cpp
    src/filter/filter.cpp
    src/stats/statistics.cpp
    src/stream/follow.cpp
    src/stream/follow_tls.cpp
    src/tls/crypto.cpp
    src/tls/keylog.cpp
    src/tls/record_decryptor.cpp
)
set_target_properties(imshark_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Live capture (libpcap; Npcap on Windows). Optional: without the library the same API is built as a stub
# that reports "Live capture is not available in this build".
option(IMSHARK_LIVE_CAPTURE "Build live packet capture (needs libpcap, or the Npcap SDK on Windows)" ON)
set(_imshark_pcap_found OFF)
if(IMSHARK_LIVE_CAPTURE)
    if(WIN32)
        # Npcap SDK: -DNPCAP_SDK_DIR=C:/npcap-sdk (or PCAP_ROOT); libraries live in Lib/x64 (Lib on x86)
        set(_pcap_roots "${NPCAP_SDK_DIR}" "$ENV{NPCAP_SDK_DIR}" "${PCAP_ROOT}" "$ENV{PCAP_ROOT}")
        find_path(PCAP_INCLUDE_DIR pcap.h HINTS ${_pcap_roots} PATH_SUFFIXES Include)
        find_library(PCAP_LIBRARY NAMES wpcap HINTS ${_pcap_roots} PATH_SUFFIXES Lib/x64 Lib)
    else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(PKG_PCAP QUIET libpcap)
        endif()
        find_path(PCAP_INCLUDE_DIR pcap.h HINTS ${PKG_PCAP_INCLUDE_DIRS})  # macOS: found in the SDK
        find_library(PCAP_LIBRARY NAMES pcap HINTS ${PKG_PCAP_LIBRARY_DIRS})
    endif()
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        set(_imshark_pcap_found ON)
    else()
        message(STATUS "libpcap not found - live capture is built as a stub")
    endif()
endif()

if(_imshark_pcap_found)
    message(STATUS "Live capture: libpcap ${PCAP_LIBRARY}")
    target_sources(imshark_core PRIVATE src/capture/live_capture_pcap.cpp)
    target_include_directories(imshark_core PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(imshark_core PUBLIC ${PCAP_LIBRARY})
    if(WIN32)
        target_link_libraries(imshark_core PUBLIC ws2_32)
    endif()
    target_compile_definitions(imshark_core PUBLIC IMSHARK_HAVE_LIVE_CAPTURE=1)
else()
    target_sources(imshark_core PRIVATE src/capture/live_capture_stub.cpp)
endif()

# TLS decryption (OpenSSL 3 libcrypto: HMAC, AES-GCM, ChaCha20-Poly1305). Optional: without the library (or with the option
# off) the same API is built as a stub that says "TLS decryption is not available in this build". OpenSSL 3 is
# Apache-2.0, which GPL-3.0 can use; it is linked dynamically unless OPENSSL_USE_STATIC_LIBS is set.
option(IMSHARK_TLS_DECRYPT "Build TLS decryption (needs OpenSSL 3 libcrypto)" ON)
set(_imshark_tls_crypto OFF)
if(IMSHARK_TLS_DECRYPT)
    if(APPLE AND NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
        foreach(_prefix /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)   # Homebrew (Apple silicon / Intel)
            if(EXISTS "${_prefix}/include/openssl/evp.h")
                set(OPENSSL_ROOT_DIR "${_prefix}")
                break()
            endif()
        endforeach()
    endif()
    find_package(OpenSSL 3 QUIET COMPONENTS Crypto)
    if(OPENSSL_FOUND)
        set(_imshark_tls_crypto ON)
    else()
        message(STATUS "OpenSSL 3 not found - TLS decryption is built as a stub")
    endif()
endif()
if(_imshark_tls_crypto)
    message(STATUS "TLS decryption: OpenSSL ${OPENSSL_VERSION} (${OPENSSL_CRYPTO_LIBRARY})")
    target_link_libraries(imshark_core PRIVATE OpenSSL::Crypto)
    target_compile_definitions(imshark_core PUBLIC IMSHARK_HAVE_TLS_DECRYPT=1)
endif()

find_package(Threads REQUIRED)  # the capture thread
target_link_libraries(imshark_core PUBLIC Threads::Threads)

target_include_directories(imshark_core PUBLIC src)

if(MSVC)
    target_compile_options(imshark_core PRIVATE /W4)
else()
    target_compile_options(imshark_core PRIVATE -Wall -Wextra)
endif()

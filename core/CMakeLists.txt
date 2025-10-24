# imshark_core: capture file readers, protocol parsing and the packet model.
# Deliberately free of any UI / OpenGL / GLFW dependency so it can be tested and reused on its own.
add_library(imshark_core STATIC
    src/capture_reader.cpp
    src/core.cpp
    src/gzip.cpp
    src/packet_parser.cpp
    src/tcp_connection.cpp
    src/network/ip_reassembly.cpp
    src/dissect/registry.cpp
    src/dissect/ip.cpp
    src/dissect/arp.cpp
    src/dissect/icmp.cpp
    src/dissect/tcp.cpp
    src/dissect/tcp_streams.cpp
    src/dissect/x509.cpp
    src/dissect/udp.cpp
    src/dissect/dns.cpp
    src/dissect/http.cpp
    src/dissect/ntp.cpp
    src/dissect/snmp.cpp
    src/dissect/tls.cpp
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
    src/export/export.cpp
    src/filter/fields.cpp
    src/filter/filter.cpp
    src/stats/statistics.cpp
    src/stream/follow.cpp
)
set_target_properties(imshark_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(imshark_core PUBLIC src)

if(MSVC)
    target_compile_options(imshark_core PRIVATE /W4)
else()
    target_compile_options(imshark_core PRIVATE -Wall -Wextra)
endif()

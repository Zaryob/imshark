# tools/compare_tshark.py: the comparator against hand-written tshark JSON (always), and the real corpus comparison
# (only where tshark is installed: the script exits 77 without it, which CTest reports as skipped).
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND AND TARGET imshark_dump)
    add_test(NAME compare_tshark_fixtures COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_compare_tshark.py)
    set_tests_properties(compare_tshark_fixtures PROPERTIES ENVIRONMENT "IMSHARK_DUMP=$<TARGET_FILE:imshark_dump>")
    add_test(NAME compare_tshark_corpus
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../tools/compare_tshark.py
                     --imshark-dump $<TARGET_FILE:imshark_dump> ${CMAKE_CURRENT_SOURCE_DIR}/corpus)
    set_tests_properties(compare_tshark_corpus PROPERTIES SKIP_RETURN_CODE 77 LABELS tshark)
endif()

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET) # FindGTest module as a fallback
endif()
if(NOT GTest_FOUND)
    message(WARNING "GoogleTest not found - unit tests are skipped (configure with -DIMSHARK_BUILD_TESTS=OFF to silence)")
    return()
endif()

add_executable(imshark_tests
    test_asn1_reader.cpp
    test_bgp.cpp
    test_capture_info.cpp
    test_capture_readers.cpp
    test_truncated_load.cpp
    test_clipboard.cpp
    test_corpus.cpp
    test_color_rules.cpp
    test_dissector_guide.cpp
    test_docs.cpp
    test_dns.cpp
    test_export.cpp
    test_filter.cpp
    test_filter_snapshot.cpp
    test_find.cpp
    test_fragments.cpp
    test_gzip.cpp
    test_http_tls.cpp
    test_hpack.cpp
    test_http2.cpp
    test_ip_reassembly.cpp
    test_datagram_reassembly.cpp
    test_dtls.cpp
    test_dtls_decrypt.cpp
    test_dtls_session.cpp
    test_follow_view.cpp
    test_misc_protocols.cpp
    test_parser.cpp
    test_reader.cpp
    test_reader_oracle.cpp
    test_reader_registry.cpp
    test_settings.cpp
    test_snmp.cpp
    test_stats.cpp
    test_stats_snapshot.cpp
    test_stream.cpp
    test_tcp.cpp
    test_tcp_reassembly.cpp
    test_tls_ports.cpp
    test_enterprise_stats.cpp
    test_tcp_options.cpp
    test_telnet.cpp
    test_smtp.cpp
    test_ftp.cpp
    test_tftp.cpp
    test_ssh.cpp
    test_session_tables.cpp
    test_checksums.cpp
    test_decode_as.cpp
    test_time_format.cpp
    test_utils.cpp
    test_ui_smoke.cpp
    test_ui_tls.cpp
    test_wlan.cpp
    test_radiotap_ppi.cpp
    test_eapol.cpp
    test_llc_stp.cpp
    test_pppoe_ppp.cpp
    test_mpls.cpp
    test_ipip_gre.cpp
    test_encap_ranges.cpp
    test_lldp_lacp.cpp
    test_live_capture.cpp
    test_hierarchy.cpp
    test_tls_crypto.cpp
    test_tls_decrypt.cpp
    test_tls_decrypt_table.cpp
    test_tls_flow.cpp
    test_tls_keylog.cpp
    test_tls_dsb.cpp
    test_tls_session.cpp
    test_xdr.cpp
    test_igmp.cpp
    test_udplite.cpp
    test_sctp.cpp
    test_sctp_chunks.cpp
    test_sctp_session.cpp
    test_sctp_reassembly.cpp
    test_ospf.cpp
    test_ipsec.cpp
    test_esp_null.cpp
    test_ike.cpp
    test_ldap.cpp
    test_kerberos.cpp
    test_spnego.cpp
    test_smb2.cpp
    test_smb2_bodies.cpp
    test_smb2_security.cpp
    test_smb2_session.cpp
    test_smb2_tables.cpp
    test_dcerpc.cpp
    test_dcerpc_session.cpp
    test_dcerpc_flows.cpp
    test_nfs.cpp
    test_postgres.cpp
    test_mysql.cpp
    test_tds.cpp
    test_usb.cpp
    test_bluetooth.cpp
    test_voip.cpp
    test_industrial.cpp
    test_file_formats.cpp
)
if(IMSHARK_SANITIZE)
    target_sources(imshark_tests PRIVATE asan_options.cpp)
endif()
target_link_libraries(imshark_tests PRIVATE imshark_core imshark_ui GTest::gtest_main)
target_compile_definitions(imshark_tests PRIVATE IMSHARK_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data"
    IMSHARK_DOCS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../docs"
    IMSHARK_GUIDE_TEST_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/test_dissector_guide.cpp")

include(GoogleTest)
gtest_discover_tests(imshark_tests DISCOVERY_MODE PRE_TEST)

# `imshark --version` prints the project version and git describe without opening a window.
add_test(NAME imshark_version COMMAND imshark --version)
set_tests_properties(imshark_version PROPERTIES PASS_REGULAR_EXPRESSION "^imshark ${PROJECT_VERSION} \\(.+\\)")

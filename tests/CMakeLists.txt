find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET) # FindGTest module as a fallback
endif()
if(NOT GTest_FOUND)
    message(WARNING "GoogleTest not found - unit tests are skipped (configure with -DIMSHARK_BUILD_TESTS=OFF to silence)")
    return()
endif()

add_executable(imshark_tests
    test_clipboard.cpp
    test_color_rules.cpp
    test_filter.cpp
    test_find.cpp
    test_fragments.cpp
    test_ip_reassembly.cpp
    test_follow_view.cpp
    test_parser.cpp
    test_reader.cpp
    test_settings.cpp
    test_stats.cpp
    test_stream.cpp
    test_tcp.cpp
    test_time_format.cpp
    test_utils.cpp
    test_ui_smoke.cpp
)
if(IMSHARK_SANITIZE)
    target_sources(imshark_tests PRIVATE asan_options.cpp)
endif()
target_link_libraries(imshark_tests PRIVATE imshark_core imshark_ui GTest::gtest_main)
target_compile_definitions(imshark_tests PRIVATE IMSHARK_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")

include(GoogleTest)
gtest_discover_tests(imshark_tests DISCOVERY_MODE PRE_TEST)

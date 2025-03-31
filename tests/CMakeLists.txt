find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest REQUIRED) # FindGTest module as a fallback
endif()

add_executable(imshark_tests
    test_parser.cpp
    test_reader.cpp
    test_tcp.cpp
    test_utils.cpp
)
if(IMSHARK_SANITIZE)
    target_sources(imshark_tests PRIVATE asan_options.cpp)
endif()
target_link_libraries(imshark_tests PRIVATE imshark_core GTest::gtest_main)
target_compile_definitions(imshark_tests PRIVATE IMSHARK_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")

include(GoogleTest)
gtest_discover_tests(imshark_tests DISCOVERY_MODE PRE_TEST)

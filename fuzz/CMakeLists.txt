# Fuzz harnesses (docs/FUZZING.md). One executable per target, each exporting LLVMFuzzerTestOneInput.
#
#  - IMSHARK_FUZZ with libFuzzer (see the top level CMakeLists.txt): the executables are real fuzzers, linked with
#    -fsanitize=fuzzer; run them with a corpus directory like any libFuzzer binary.
#  - Everything else (normal builds, MSVC, GCC, Apple Clang): the executables link standalone_main.cpp, which runs every
#    file given on the command line once. They are compiled and replayed over the seed corpus in every CI configuration,
#    so a harness cannot rot and a regression on a corpus input fails the normal test run.
#
# Both engines accept `harness -runs=0 corpus-directory` (the standalone driver ignores options), which is what CTest runs.

set(IMSHARK_FUZZ_HARNESSES
    fuzz_capture_file
    fuzz_packet
    fuzz_packet_sequence
    fuzz_filter
    fuzz_gzip
)

foreach(harness IN LISTS IMSHARK_FUZZ_HARNESSES)
    if(IMSHARK_FUZZ_LIBFUZZER)
        add_executable(${harness} ${harness}.cpp)
        target_link_options(${harness} PRIVATE -fsanitize=fuzzer)
    else()
        add_executable(${harness} ${harness}.cpp standalone_main.cpp)
    endif()
    target_link_libraries(${harness} PRIVATE imshark_core)
    target_include_directories(${harness} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MSVC)
        target_compile_options(${harness} PRIVATE /W4)
    else()
        target_compile_options(${harness} PRIVATE -Wall -Wextra)
    endif()

    add_test(NAME fuzz_replay_${harness}
             COMMAND ${harness} -runs=0 "-artifact_prefix=${CMAKE_CURRENT_BINARY_DIR}/" "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${harness}")
    set_tests_properties(fuzz_replay_${harness} PROPERTIES LABELS fuzz TIMEOUT 600)
endforeach()

# Builds every harness: cmake --build --preset fuzz   (or --target imshark_fuzzers)
add_custom_target(imshark_fuzzers DEPENDS ${IMSHARK_FUZZ_HARNESSES})

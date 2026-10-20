cmake_minimum_required(VERSION 3.21)
project(imshark_windows_capture_validation LANGUAGES CXX)
if(NOT WIN32)
    message(FATAL_ERROR "This validation requires native Windows APIs")
endif()
get_filename_component(IMSHARK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
if(MSVC)
    add_compile_options(/utf-8 /Zc:__cplusplus /W4 /Gy)
endif()
set(CAPTURE_DIR "${IMSHARK_ROOT}/core/src/capture")
add_executable(windows_capture_smoke
    "${IMSHARK_ROOT}/tests/windows_capture_smoke.cpp"
    "${CAPTURE_DIR}/capture_worker.cpp"
    "${CAPTURE_DIR}/worker_launch.cpp"
    "${CAPTURE_DIR}/live_capture.cpp"
    "${CAPTURE_DIR}/live_capture_stream.cpp"
    "${CAPTURE_DIR}/live_capture_stub.cpp"
    "${CAPTURE_DIR}/pcap_stream.cpp"
    "${IMSHARK_ROOT}/core/src/temp_file.cpp")
target_include_directories(windows_capture_smoke PRIVATE "${IMSHARK_ROOT}/core/src")
target_link_libraries(windows_capture_smoke PRIVATE shell32 advapi32 ole32)
# Compile the Npcap-enabled production backend too, even on runners without an installed driver.
# A separate executable checks native headers, APIs and import libraries without claiming a driver run.
if(NPCAP_SDK_DIR)
    add_executable(npcap_link_check
        "${IMSHARK_ROOT}/tests/windows_capture_smoke.cpp"
        "${CAPTURE_DIR}/capture_worker.cpp" "${CAPTURE_DIR}/worker_launch.cpp"
        "${CAPTURE_DIR}/live_capture.cpp" "${CAPTURE_DIR}/live_capture_stream.cpp"
        "${CAPTURE_DIR}/live_capture_pcap.cpp" "${CAPTURE_DIR}/pcap_stream.cpp"
        "${IMSHARK_ROOT}/core/src/temp_file.cpp")
    target_include_directories(npcap_link_check PRIVATE "${IMSHARK_ROOT}/core/src" "${NPCAP_SDK_DIR}/Include")
    target_compile_definitions(npcap_link_check PRIVATE IMSHARK_HAVE_LIVE_CAPTURE=1)
    target_link_libraries(npcap_link_check PRIVATE "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib" ws2_32 shell32 advapi32 ole32)
endif()
enable_testing()
add_test(NAME windows_capture_native_ipc COMMAND windows_capture_smoke)
set_tests_properties(windows_capture_native_ipc PROPERTIES TIMEOUT 45)

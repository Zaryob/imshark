cmake_minimum_required(VERSION 3.21)

project(imshark VERSION 0.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/utf-8 /Zc:__cplusplus)     # sources are UTF-8; report the real __cplusplus
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# Instrumentation options must be set before the subdirectories are added: add_compile_options() only affects
# targets created after it, so putting them below would leave imshark_core (and ImGui) uninstrumented.
option(IMSHARK_BUILD_TESTS "Build the unit tests (requires GoogleTest)" ON)
option(IMSHARK_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(IMSHARK_BUILD_TOOLS "Build tools/imshark_dump (headless field dump used by tools/compare_tshark.py)" ON)
option(IMSHARK_BUILD_BENCH "Build tools/bench_driver (headless load + filter benchmark, see tools/benchmark.py)" OFF)
option(IMSHARK_COVERAGE "Instrument for source based code coverage (clang): see tools/coverage.sh" OFF)
if(IMSHARK_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "IMSHARK_COVERAGE needs clang")
    endif()
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate)
endif()

if(IMSHARK_SANITIZE AND MSVC)
    message(WARNING "IMSHARK_SANITIZE is only supported with GCC/Clang - ignoring")
elseif(IMSHARK_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(core)          # imshark_core: parsing library (no UI dependencies)
add_subdirectory(third_party)   # imshark_imgui: Dear ImGui, backends, ImGuiFileDialog

# Guard: a sanitizer / coverage build that silently skips the core would give false confidence.
get_target_property(_core_options imshark_core COMPILE_OPTIONS)
if(IMSHARK_SANITIZE AND NOT MSVC AND NOT "${_core_options}" MATCHES "fsanitize")
    message(FATAL_ERROR "IMSHARK_SANITIZE is on but imshark_core is not instrumented: keep the option block above add_subdirectory()")
endif()
if(IMSHARK_COVERAGE AND NOT "${_core_options}" MATCHES "fprofile-instr-generate")
    message(FATAL_ERROR "IMSHARK_COVERAGE is on but imshark_core is not instrumented: keep the option block above add_subdirectory()")
endif()

# The UI (everything except window/GL setup) is a library so it can be smoke-tested without a window.
add_library(imshark_ui STATIC
    src/ui/capture_info_window.cpp
    src/ui/chrome.cpp
    src/ui/color_editor.cpp
    src/ui/color_rules.cpp
    src/ui/decode_as.cpp
    src/ui/clipboard.cpp
    src/ui/details.cpp
    src/ui/export_dialog.cpp
    src/ui/find.cpp
    src/ui/find_bar.cpp
    src/ui/follow_view.cpp
    src/ui/follow_window.cpp
    src/ui/filter_bar.cpp
    src/ui/live_capture.cpp
    src/ui/loader.cpp
    src/ui/main_window.cpp
    src/ui/packet_list.cpp
    src/ui/preferences.cpp
    src/ui/settings.cpp
    src/ui/stats_windows.cpp
    src/ui/time_format.cpp
)
target_include_directories(imshark_ui PUBLIC src)
target_link_libraries(imshark_ui PUBLIC imshark_core imshark_imgui)

# Version string for `imshark --version`: the project version plus `git describe` captured at configure time
# ("unknown" outside a git checkout, e.g. a source tarball). Re-run cmake to refresh it after new commits.
find_package(Git QUIET)
set(IMSHARK_GIT_DESCRIBE "unknown")
if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _git_describe OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _git_rc ERROR_QUIET)
    if(_git_rc EQUAL 0 AND NOT _git_describe STREQUAL "")
        set(IMSHARK_GIT_DESCRIBE "${_git_describe}")
    endif()
endif()
configure_file(src/version.h.in "${CMAKE_BINARY_DIR}/generated/version.h" @ONLY)

add_executable(imshark src/main.cpp)
target_include_directories(imshark PRIVATE "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(imshark PRIVATE imshark_ui)
if(APPLE)
    target_compile_definitions(imshark PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(IMSHARK_BUILD_TOOLS)
    add_executable(imshark_dump tools/imshark_dump.cpp)
    target_link_libraries(imshark_dump PRIVATE imshark_core)
endif()

if(IMSHARK_BUILD_BENCH)
    add_executable(bench_driver tools/bench_driver.cpp)
    target_link_libraries(bench_driver PRIVATE imshark_core)   # same link line as the application's core dependencies
endif()

if(IMSHARK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()


# macOS .app bundle
if(APPLE)
    set_target_properties(imshark PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "ImShark"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_IDENTIFIER "com.imshark.app"
        MACOSX_BUNDLE_COPYRIGHT "GPL-3.0"
    )
endif()

# The install rule must come after MACOSX_BUNDLE is set on the target: CMake decides RUNTIME vs BUNDLE when install()
# is processed. On macOS BUNDLE DESTINATION puts imshark.app at the top of the package (otherwise the DragNDrop image
# holds bin/imshark.app); elsewhere the executable goes to bin/. Shared libraries (GLFW, OpenSSL) are not bundled.
install(TARGETS imshark RUNTIME DESTINATION bin BUNDLE DESTINATION .)

# CPack packaging
set(CPACK_PACKAGE_NAME "imshark")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ImShark - Network Packet Analyzer")
set(CPACK_PACKAGE_VENDOR "imshark contributors")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "ImShark")

if(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
elseif(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ;DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "imshark contributors")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libgl1, libglfw3")
endif()

include(CPack)

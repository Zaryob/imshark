cmake_minimum_required(VERSION 3.21)

# Select the manifest toolchain before project(), where vcpkg resolves dependencies.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "vcpkg toolchain")
endif()
if(NOT CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "Set VCPKG_ROOT to a bootstrapped vcpkg checkout and run cmake --preset default. See docs/BUILDING.md.")
endif()
option(IMSHARK_BUILD_TESTS "Build the GoogleTest regression suite" ON)
option(IMSHARK_TLS_DECRYPT "Build TLS/DTLS decryption with OpenSSL 3" ON)
set(_live_default ON)
if(CMAKE_HOST_WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(_live_default OFF)
endif()
option(IMSHARK_LIVE_CAPTURE "Build live capture (Npcap SDK required on Windows)" ${_live_default})
# Keep the manifest features aligned with the CMake options, including reconfiguration.
set(VCPKG_MANIFEST_NO_DEFAULT_FEATURES ON)
set(VCPKG_MANIFEST_FEATURES "")
if(IMSHARK_BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES tests)
endif()
if(IMSHARK_TLS_DECRYPT)
    list(APPEND VCPKG_MANIFEST_FEATURES tls-decrypt)
endif()
if(IMSHARK_LIVE_CAPTURE)
    list(APPEND VCPKG_MANIFEST_FEATURES live-capture)
endif()

project(imshark VERSION 0.9.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/utf-8 /Zc:__cplusplus)     # sources are UTF-8; report the real __cplusplus
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# Instrumentation options must be set before the subdirectories are added: add_compile_options() only affects
# targets created after it, so putting them below would leave imshark_core and the UI uninstrumented.
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

# Fuzzing (docs/FUZZING.md). The harnesses in fuzz/ are always built next to the tests and replay their seed corpus under
# CTest. IMSHARK_FUZZ additionally instruments the whole build for coverage guided fuzzing with libFuzzer and
# ASan/UBSan; it needs Clang with the libFuzzer runtime (Apple Clang has none: use Homebrew LLVM, see the fuzz-macos
# preset). Without that engine the harnesses link the standalone driver fuzz/standalone_main.cpp, which only replays files.
option(IMSHARK_FUZZ "Build the fuzz harnesses with libFuzzer, AddressSanitizer and UndefinedBehaviorSanitizer (Clang)" OFF)
set(IMSHARK_FUZZ_ENGINE "AUTO" CACHE STRING "Engine for IMSHARK_FUZZ: AUTO (libFuzzer if the compiler has it), LIBFUZZER (required) or STANDALONE (replay driver)")
set_property(CACHE IMSHARK_FUZZ_ENGINE PROPERTY STRINGS AUTO LIBFUZZER STANDALONE)
set(IMSHARK_FUZZ_LIBFUZZER OFF)
if(IMSHARK_FUZZ AND NOT IMSHARK_FUZZ_ENGINE STREQUAL "STANDALONE")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        include(CheckCXXSourceCompiles)
        set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer,address,undefined")
        check_cxx_source_compiles("#include <cstddef>\n#include <cstdint>\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) { return 0; }\n"
                                  IMSHARK_HAVE_LIBFUZZER)
        unset(CMAKE_REQUIRED_FLAGS)
    endif()
    if(IMSHARK_HAVE_LIBFUZZER)
        set(IMSHARK_FUZZ_LIBFUZZER ON)
    elseif(IMSHARK_FUZZ_ENGINE STREQUAL "LIBFUZZER")
        message(FATAL_ERROR "IMSHARK_FUZZ_ENGINE=LIBFUZZER but ${CMAKE_CXX_COMPILER} (${CMAKE_CXX_COMPILER_ID}) cannot build with -fsanitize=fuzzer. "
                            "Use Clang with the libFuzzer runtime (Apple Clang has none; see docs/FUZZING.md).")
    else()
        message(WARNING "IMSHARK_FUZZ is on but the compiler has no libFuzzer: the harnesses are built with the standalone replay driver")
    endif()
endif()
if(IMSHARK_FUZZ_LIBFUZZER)
    # fuzzer-no-link adds the coverage instrumentation the engine steers by; the engine itself is linked into the harnesses only.
    # -O1 is what libFuzzer recommends; -fno-sanitize-recover makes undefined behaviour a crash the fuzzer can save.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -O1)
    add_compile_definitions(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Fuzzing: libFuzzer + ASan + UBSan")
elseif(IMSHARK_FUZZ)
    message(STATUS "Fuzzing: standalone replay driver")
endif()

if(IMSHARK_SANITIZE AND MSVC)
    message(WARNING "IMSHARK_SANITIZE is only supported with GCC/Clang - ignoring")
elseif(IMSHARK_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# Warning set for project code only (vcpkg dependencies and generated code are not linked against this target).
option(IMSHARK_WERROR "Treat compiler warnings in project code as errors (GCC/Clang only)" OFF)
add_library(imshark_warnings INTERFACE)
if(MSVC)
    # /W4 only: IMSHARK_WERROR does not add /WX until the MSVC build of the UI is verified warning-free.
    target_compile_options(imshark_warnings INTERFACE /W4)
else()
    target_compile_options(imshark_warnings INTERFACE -Wall -Wextra -Wshadow -Wnon-virtual-dtor)
    if(IMSHARK_WERROR)
        target_compile_options(imshark_warnings INTERFACE -Werror)
    endif()
endif()

add_subdirectory(core)          # imshark_core: parsing library (no UI dependencies)
include(cmake/Dependencies.cmake) # ImGui, backends and file dialogs from vcpkg

# Guard: a sanitizer / coverage build that silently skips the core would give false confidence.
get_target_property(_core_options imshark_core COMPILE_OPTIONS)
if(IMSHARK_SANITIZE AND NOT MSVC AND NOT "${_core_options}" MATCHES "fsanitize")
    message(FATAL_ERROR "IMSHARK_SANITIZE is on but imshark_core is not instrumented: keep the option block above add_subdirectory()")
endif()
if(IMSHARK_FUZZ_LIBFUZZER AND NOT "${_core_options}" MATCHES "fsanitize=fuzzer-no-link")
    message(FATAL_ERROR "IMSHARK_FUZZ is on but imshark_core is not instrumented: keep the option block above add_subdirectory()")
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
    src/ui/theme.cpp
    src/ui/time_format.cpp
)
target_include_directories(imshark_ui PUBLIC src)
target_link_libraries(imshark_ui PUBLIC imshark_core imshark_imgui PRIVATE imshark_warnings)

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

# Embed the PNGs so branding also works from an arbitrary working directory and in installed packages.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/welcome-logo.png"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/welcome-logo-light.png"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.png")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/resources/welcome-logo.png" _logo_hex HEX)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/resources/welcome-logo-light.png" _logo_light_hex HEX)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.png" _icon_hex HEX)
string(REGEX REPLACE "(..)" "0x\\1," IMSHARK_LOGO_BYTES "${_logo_hex}")
string(REGEX REPLACE "(..)" "0x\\1," IMSHARK_LOGO_LIGHT_BYTES "${_logo_light_hex}")
string(REGEX REPLACE "(..)" "0x\\1," IMSHARK_ICON_BYTES "${_icon_hex}")
configure_file(src/brand_assets.h.in "${CMAKE_BINARY_DIR}/generated/brand_assets.h" @ONLY)

add_executable(imshark src/main.cpp)
find_package(Stb REQUIRED)
target_include_directories(imshark PRIVATE ${Stb_INCLUDE_DIR})
target_include_directories(imshark PRIVATE "${CMAKE_BINARY_DIR}/generated")
target_link_libraries(imshark PRIVATE imshark_ui imshark_warnings)
if(APPLE)
    target_compile_definitions(imshark PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(IMSHARK_BUILD_TOOLS)
    add_executable(imshark_dump tools/imshark_dump.cpp)
    target_link_libraries(imshark_dump PRIVATE imshark_core imshark_warnings)
endif()

if(IMSHARK_BUILD_BENCH)
    add_executable(bench_driver tools/bench_driver.cpp)
    target_link_libraries(bench_driver PRIVATE imshark_core)   # same link line as the application's core dependencies
endif()

if(IMSHARK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Fuzz harnesses: compiled in every configuration with tests, and replayed over their seed corpus as CTest tests.
if(IMSHARK_BUILD_TESTS OR IMSHARK_FUZZ)
    enable_testing()
    add_subdirectory(fuzz)
endif()


# macOS .app bundle
if(APPLE)
    set_target_properties(imshark PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "ImShark"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_GUI_IDENTIFIER "io.github.zaryob.imshark"
        MACOSX_BUNDLE_ICON_FILE "imshark.icns"
        MACOSX_BUNDLE_COPYRIGHT "GPL-3.0"
    )
    target_sources(imshark PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.icns")
    set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.icns" PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
elseif(WIN32)
    enable_language(RC)
    target_sources(imshark PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.rc")
    target_include_directories(imshark PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/resources")
endif()

# The install rule must come after MACOSX_BUNDLE is set on the target: CMake decides RUNTIME vs BUNDLE when install()
# is processed. On macOS BUNDLE DESTINATION puts imshark.app at the top of the package (otherwise the DragNDrop image
# holds bin/imshark.app); elsewhere the executable goes to bin/.
if(WIN32)
    # Include app-local vcpkg DLLs in the ZIP alongside the executable.
    install(TARGETS imshark
        RUNTIME_DEPENDENCIES
            DIRECTORIES "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin"
            PRE_EXCLUDE_REGEXES "api-ms-.*" "ext-ms-.*"
            POST_EXCLUDE_REGEXES ".*[Ww][Ii][Nn][Dd][Oo][Ww][Ss][/\\\\][Ss][Yy][Ss][Tt][Ee][Mm]32.*"
        RUNTIME DESTINATION bin)
    include(InstallRequiredSystemLibraries)
else()
    install(TARGETS imshark RUNTIME DESTINATION bin BUNDLE DESTINATION .)
endif()
if(UNIX AND NOT APPLE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.desktop" DESTINATION share/applications)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/resources/imshark.png" DESTINATION share/icons/hicolor/256x256/apps)
endif()
if(APPLE)
    set(_license_root "imshark.app/Contents/Resources")
else()
    set(_license_root "share/imshark")
endif()
install(FILES LICENSE DESTINATION "${_license_root}")
# Include the full installed dependency closure (GLFW also links X11/Wayland libraries on Linux).
file(GLOB _dependency_notices "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share/*/copyright")
foreach(_notice IN LISTS _dependency_notices)
    get_filename_component(_port_share "${_notice}" DIRECTORY)
    get_filename_component(_port "${_port_share}" NAME)
    install(FILES "${_notice}" DESTINATION "${_license_root}/licenses" RENAME "${_port}.txt")
endforeach()
# The vcpkg pcre2 notice only points at the LICENCE file of the source tree, so the full text ships with the package.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/resources/licenses/pcre2-LICENCE.md" DESTINATION "${_license_root}/licenses")

# macOS: make the installed bundle self-contained. fixup_bundle copies every non-system dylib the executable links
# (GLFW, OpenSSL libcrypto, libpcap/zlib if they are not system ones) into Contents/Frameworks and rewrites the install
# names. Linux uses static vcpkg libraries plus OS graphics/runtime libraries; AppImage bundles the latter.
if(APPLE)
    install(CODE "
        include(BundleUtilities)
        set(_app \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/imshark.app\")
        fixup_bundle(\"\${_app}\" \"\" \"${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib\")
        # install_name_tool invalidated the signatures, and Apple Silicon kills unsigned code: re-sign ad hoc.
        # This is NOT a Developer ID signature and the image is not notarized (Gatekeeper still warns on download).
        execute_process(COMMAND codesign --force --deep --sign - \"\${_app}\" RESULT_VARIABLE _sign_rc)
        if(NOT _sign_rc EQUAL 0)
            message(FATAL_ERROR \"ad-hoc codesign of the bundle failed (\${_sign_rc})\")
        endif()
    ")
endif()

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
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    # GLFW opens these native desktop libraries with dlopen; shlibdeps cannot see them.
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libgl1, libx11-6, libxrandr2, libxinerama1, libxcursor1, libxi6, libxrender1")
endif()

include(CPack)

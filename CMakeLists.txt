cmake_minimum_required(VERSION 3.21)

project(imshark VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/utf-8 /Zc:__cplusplus)     # sources are UTF-8; report the real __cplusplus
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

add_subdirectory(core)          # imshark_core: parsing library (no UI dependencies)
add_subdirectory(third_party)   # imshark_imgui: Dear ImGui, backends, ImGuiFileDialog

option(IMSHARK_BUILD_TESTS "Build the unit tests (requires GoogleTest)" ON)
option(IMSHARK_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(IMSHARK_SANITIZE AND MSVC)
    message(WARNING "IMSHARK_SANITIZE is only supported with GCC/Clang - ignoring")
elseif(IMSHARK_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# The UI (everything except window/GL setup) is a library so it can be smoke-tested without a window.
add_library(imshark_ui STATIC
    src/ui/chrome.cpp
    src/ui/color_editor.cpp
    src/ui/color_rules.cpp
    src/ui/clipboard.cpp
    src/ui/details.cpp
    src/ui/find.cpp
    src/ui/find_bar.cpp
    src/ui/follow_view.cpp
    src/ui/follow_window.cpp
    src/ui/filter_bar.cpp
    src/ui/loader.cpp
    src/ui/main_window.cpp
    src/ui/packet_list.cpp
    src/ui/settings.cpp
    src/ui/stats_windows.cpp
    src/ui/time_format.cpp
)
target_include_directories(imshark_ui PUBLIC src)
target_link_libraries(imshark_ui PUBLIC imshark_core imshark_imgui)

add_executable(imshark src/main.cpp)
target_link_libraries(imshark PRIVATE imshark_ui)
if(APPLE)
    target_compile_definitions(imshark PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(IMSHARK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS imshark RUNTIME DESTINATION bin)

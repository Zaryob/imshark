cmake_minimum_required(VERSION 3.21)

project(imshark VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(core)          # imshark_core: parsing library (no UI dependencies)
add_subdirectory(third_party)   # imshark_imgui: Dear ImGui, backends, ImGuiFileDialog

option(IMSHARK_BUILD_TESTS "Build the unit tests (requires GoogleTest)" ON)
option(IMSHARK_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(IMSHARK_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

add_executable(imshark src/main.cpp)
target_link_libraries(imshark PRIVATE imshark_core imshark_imgui)
if(APPLE)
    target_compile_definitions(imshark PRIVATE GL_SILENCE_DEPRECATION)
endif()

if(IMSHARK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS imshark RUNTIME DESTINATION bin)

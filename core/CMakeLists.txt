cmake_minimum_required(VERSION 3.13)
project(pcap_core)

# Main code
file(GLOB_RECURSE SRC "src/*.cpp" "src/*.c")

# Add code to dyn lib
add_library(pcap_core SHARED ${SRC})

# Set compiler options
target_compile_options(pcap_core PRIVATE ${PCAPGUI_COMPILER_FLAGS})

# Set the install prefix
target_compile_definitions(pcap_core PUBLIC INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}")

# Include core headers
target_include_directories(pcap_core PUBLIC "src/")
target_include_directories(pcap_core PUBLIC "src/imgui")


# Install directives
install(TARGETS pcap_core DESTINATION lib)

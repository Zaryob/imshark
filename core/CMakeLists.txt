cmake_minimum_required(VERSION 3.13)
project(imshark_core)

# Main code
file(GLOB_RECURSE SRC "src/*.cpp" "src/*.c")

# Configure backend sources
file(GLOB_RECURSE BACKEND_SRC "backends/glfw/imgui/*.cpp" "backends/glfw/imgui/*.c")

# Configure imgui sources
file(GLOB_RECURSE IMGUI_SRC "src/imgui/*.cpp" "src/imgui/*.c")

# Add code to dyn lib
add_library(imshark_core SHARED ${SRC} ${BACKEND_SRC} ${IMGUI_SRC})

# Set compiler options
target_compile_options(imshark_core PRIVATE ${imsharkGUI_COMPILER_FLAGS})

# Set the install prefix
target_compile_definitions(imshark_core PUBLIC INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}")

# Include core headers
target_include_directories(imshark_core PUBLIC "src/")
target_include_directories(imshark_core PUBLIC "src/imgui")
target_include_directories(imshark_core PUBLIC "backends/glfw/imgui")

find_package(OpenGL REQUIRED)
target_link_libraries(imshark_core PUBLIC OpenGL::GL)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW3 REQUIRED glfw3)
target_include_directories(imshark_core PUBLIC ${GLFW3_INCLUDE_DIRS})
target_link_directories(imshark_core PUBLIC ${GLFW3_LIBRARY_DIRS})
target_link_libraries(imshark_core PUBLIC ${GLFW3_LIBRARIES})


# Install directives
install(TARGETS imshark_core DESTINATION lib)

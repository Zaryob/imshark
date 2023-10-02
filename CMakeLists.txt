cmake_minimum_required(VERSION 3.5)

project(imshark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(core)

add_executable(imshark src/main.cpp)
target_include_directories(imshark PRIVATE ${CMAKE_CURRENT_LIST_DIR}/)
target_link_libraries(imshark PRIVATE imshark_core)

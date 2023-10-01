cmake_minimum_required(VERSION 3.5)

project(pcapgui LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(core)

add_executable(pcapgui src/main.cpp)
target_include_directories(pcapgui PRIVATE ${CMAKE_CURRENT_LIST_DIR}/)
target_link_libraries(pcapgui PRIVATE pcap_core)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW3 REQUIRED glfw3)
target_include_directories(pcapgui PUBLIC ${GLFW3_INCLUDE_DIRS})
target_link_directories(pcapgui PUBLIC ${GLFW3_LIBRARY_DIRS})
target_link_libraries(pcapgui PUBLIC ${GLFW3_LIBRARIES})

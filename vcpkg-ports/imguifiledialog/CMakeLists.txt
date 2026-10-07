cmake_minimum_required(VERSION 3.21)
project(imguifiledialog VERSION 0.6.8 LANGUAGES CXX)
find_package(imgui CONFIG REQUIRED)
add_library(imguifiledialog STATIC ImGuiFileDialog.cpp)
target_compile_features(imguifiledialog PUBLIC cxx_std_17)
target_compile_definitions(imguifiledialog PUBLIC USE_STD_FILESYSTEM)
target_link_libraries(imguifiledialog PUBLIC imgui::imgui)
target_include_directories(imguifiledialog PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS imguifiledialog EXPORT imguifiledialog-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ImGuiFileDialog.h ImGuiFileDialogConfig.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT imguifiledialog-targets NAMESPACE imguifiledialog:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/imguifiledialog)
configure_package_config_file(imguifiledialog-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/imguifiledialog-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/imguifiledialog)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/imguifiledialog-config.cmake" DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/imguifiledialog)

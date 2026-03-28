# Vendored UI dependencies: Dear ImGui (+ GLFW/OpenGL3 backends) and ImGuiFileDialog.
add_library(imshark_imgui STATIC
    imgui/imgui.cpp
    imgui/imgui_demo.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/imgui_impl_glfw.cpp
    imgui/imgui_impl_opengl3.cpp
    ImGuiFileDialog/ImGuiFileDialog.cpp
)

# `SYSTEM` keeps warnings of vendored code out of our build output.
target_include_directories(imshark_imgui SYSTEM PUBLIC imgui ImGuiFileDialog)

# GLFW: prefer the CMake package config (vcpkg, Homebrew, most distros), fall back to pkg-config.
find_package(OpenGL REQUIRED)
find_package(glfw3 CONFIG QUIET)
if(TARGET glfw)
    message(STATUS "Using GLFW from CMake package config")
    target_link_libraries(imshark_imgui PUBLIC glfw)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLFW3 REQUIRED glfw3)
    target_include_directories(imshark_imgui SYSTEM PUBLIC ${GLFW3_INCLUDE_DIRS})
    target_link_directories(imshark_imgui PUBLIC ${GLFW3_LIBRARY_DIRS})
    target_link_libraries(imshark_imgui PUBLIC ${GLFW3_LIBRARIES})
endif()
target_link_libraries(imshark_imgui PUBLIC OpenGL::GL)

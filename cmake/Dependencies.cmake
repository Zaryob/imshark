# All third-party libraries are provided by the pinned vcpkg manifest.
find_package(imgui CONFIG REQUIRED)
find_package(imguifiledialog CONFIG REQUIRED)
find_package(glfw3 CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
add_library(imshark_imgui INTERFACE)
target_link_libraries(imshark_imgui INTERFACE
    imgui::imgui imguifiledialog::imguifiledialog glfw OpenGL::GL)

# imshark_core: capture file readers, protocol parsing and the packet model.
# Deliberately free of any UI / OpenGL / GLFW dependency so it can be tested and reused on its own.
add_library(imshark_core STATIC
    src/core.cpp
    src/packet_parser.cpp
    src/tcp_connection.cpp
)
set_target_properties(imshark_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(imshark_core PUBLIC src)

if(MSVC)
    target_compile_options(imshark_core PRIVATE /W4)
else()
    target_compile_options(imshark_core PRIVATE -Wall -Wextra)
endif()

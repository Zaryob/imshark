vcpkg_check_linkage(ONLY_STATIC_LIBRARY)
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO aiekick/ImGuiFileDialog
    REF "v${VERSION}"
    SHA512 8bab17a1d11e8b9a730ff5b02c542c9f96cd71a665377507a61c8fb5d743ac0ff60a4049a5c31df8ead58c600534eb97e6e35ce836a1da93415cd80a746edd5c
)
file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" "${CMAKE_CURRENT_LIST_DIR}/imguifiledialog-config.cmake.in" DESTINATION "${SOURCE_PATH}")
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}")
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME imguifiledialog CONFIG_PATH lib/cmake/imguifiledialog)
vcpkg_copy_pdbs()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")

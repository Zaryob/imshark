# Validation record — 8–9 October 2026

This record describes local verification of ImShark 0.8.0 during the vcpkg migration. It does not report a completed GitHub Actions run. Reproduction instructions are in [BUILDING.md](BUILDING.md).

## Dependency inputs

Registry baseline: `2750401336fb7c95f6619657a46a7e798661341c`.

| Dependency | Resolved version |
|---|---|
| Dear ImGui | 1.92.9b (vcpkg port 1.92.9) |
| ImGuiFileDialog | 0.6.8, checked-in vcpkg overlay |
| GLFW | 3.5.1 |
| OpenSSL | 3.6.5 |
| libpcap | 1.10.7 |
| GoogleTest | 1.18.0 |

All C/C++ libraries used by the verified default build were resolved through the manifest. Operating-system compilers, native display headers and graphics/runtime libraries remain platform requirements. Optional Windows live capture requires a separately obtained Npcap SDK and installed driver; it was not part of this verification.

## macOS tests

Environment: arm64 macOS 27.0, Apple Clang 21.0.0 (`clang-2100.3.34.2`), libc++, vcpkg triplet `arm64-osx`.

| Configuration | Registered tests | Passed | Skipped | Failed | Time |
|---|---:|---:|---:|---:|---:|
| Release (`default`), final UI/snapshot changes | 1,295 | 1,267 | 28 | 0 | 30.71 s |
| Release (`minimal`), final sources, TLS/live capture disabled | 1,295 | 1,157 | 138 | 0 | 90.85 s |
| Debug, ASan + UBSan | 1,295 | 1,267 | 28 | 0 | 575.21 s |

```sh
ctest --preset default
cmake --preset debug -DIMSHARK_SANITIZE=ON
cmake --build --preset debug
ctest --preset debug
```

After the final UI/snapshot changes, the Debug ASan/UBSan build also passed all 60 selected `Docs`, `StatsSnapshot` and `UiSmoke` tests in 7.10 seconds. The minimal snapshot check compares every endpoint, conversation and outer protocol layer; descendants of TLS nodes are expected only when the cryptography backend is enabled.

The `UiInteract` tests (`tests/test_ui_interactions.cpp`) drive the real ImGui widgets headless with synthetic mouse and key events: menu bar entries, right-click menus of the packet list, protocol tree and hex view (copy, Follow Stream), dropped files (capture, gzip, missing, non-capture, unsaved live capture) and exports in every range and format with the packet counts read back from the written files.

The final NFS timestamp portability, packet-length comparisons, formatting buffers and HKDF-label changes also passed 211 selected regression tests (209 passed, 2 optional real-capture checks skipped): 6.00 seconds in Release and 41.94 seconds under ASan/UBSan.

Each suite ran serially. The additional minimal-build skips cover decryption-dependent tests. The other skips cover unavailable real captures and tshark, the permission-dependent live loopback test, and fallback tests for disabled backends that do not apply when those backends are enabled. They are not evidence that those optional environments passed.

A separate ASan/UBSan probe compiled the final clipboard source and passed empty/out-of-range selections, `SIZE_MAX` lengths and offsets, hex/ASCII conversion, and multiline hex-dump formatting. This verifies the final clipboard bounds fix in addition to the full Debug run above.

## macOS package

```sh
cmake --preset default
cmake --build --preset default
cmake --install build --prefix .cache/install-macos
codesign --verify --deep --strict .cache/install-macos/imshark.app
.cache/install-macos/imshark.app/Contents/MacOS/imshark --version
otool -L .cache/install-macos/imshark.app/Contents/MacOS/imshark
(cd build && cpack -C Release)
```

The install completed `fixup_bundle` verification, the ad hoc signature passed verification, and the installed executable reported `imshark 0.8.0`. Its dynamic dependency list contained only macOS system libraries/frameworks. Dependency notices were present inside `imshark.app/Contents/Resources/licenses/`. CPack produced `build/imshark-0.8.0-Darwin.dmg`.

This package is ad hoc signed; Developer ID signing, notarization and testing on a separate clean macOS machine remain release work.

## Linux Docker build and package

Environment: Ubuntu 24.04, aarch64, GCC 13.3, libstdc++; the image was built natively on an arm64 Docker host.

```sh
docker build --target verify -t imshark-linux-verify .
```

The image build resolved 32 vcpkg ports, built the Release application and ran all 1,295 registered tests serially: **1,268 passed, 27 skipped, 0 failed**, in 11.65 seconds. The installed executable reported `imshark 0.8.0 (unknown)`; the source archive intentionally excludes `.git`, so no revision is embedded. CPack produced `imshark-0.8.0-Linux.tar.gz` and `imshark-0.8.0-Linux.deb`, including generated DEB runtime dependencies.

The final GCC build emitted no compiler warnings. Running the verification image again with networking disabled repeated the full suite: **1,268 passed, 27 skipped, 0 failed**, in 9.89 seconds. Under Xvfb and Mesa llvmpipe (OpenGL 4.5), the installed application loaded all 16 packets from `tests/data/sample.pcap`, rendered the UI and exited successfully after a window-manager close request.

```sh
docker run --rm --init --network none imshark-linux-verify
docker build --target package-verify -t imshark-linux-package .
docker run --rm --init --network none imshark-linux-package
```

The `package-verify` stage installed the generated DEB in a fresh Ubuntu 24.04 image with its declared runtime dependencies and display-test tools. It contains no compiler, vcpkg checkout or application build tree. `/usr/bin/imshark` passed the same offline GUI smoke test: sample loaded, OpenGL rendered, graceful shutdown. The DEB explicitly declares the X11/OpenGL libraries GLFW loads dynamically, in addition to the libraries found by `dpkg-shlibdeps`.

[The README screenshot](images/imshark-linux.png) was captured from this clean package installation. Full local logs and smoke artifacts are kept in the ignored `.cache/` and `artifacts/linux{,-package}/` directories; CI uploads the smoke artifacts.

This proves the aarch64 container build, package generation and clean Ubuntu package startup. Windows, Linux x86_64, AppImage execution, physical live-capture devices and hardware GPU rendering were not exercised locally.

## Third-party licence notices in the published packages

Audit of the assets of [v0.9.2](https://github.com/Zaryob/imshark/releases/tag/v0.9.2), 10 October 2026. All five assets were downloaded with `gh release download v0.9.2` and matched `SHA256SUMS.txt`. The notices a package ships are the `licenses/*.txt` files (and `LICENSE` for ImShark itself) that the install rules in `CMakeLists.txt` copy from the vcpkg `share/<port>/copyright` files.

What the code actually uses at run time (`vcpkg.json`, `cmake/Dependencies.cmake`, `CMakeLists.txt`): Dear ImGui and ImGuiFileDialog (statically linked), GLFW, OpenGL (system), OpenSSL for TLS/DTLS decryption, libpcap for live capture on Linux and macOS. Gzip uses ImShark's own inflate implementation, so zlib is not a dependency. GoogleTest is linked only into the test executable. `stb` (header-only, public domain or MIT, used for `stb_image` in `src/main.cpp`) was added with the branding work after 0.9.2 and is not in any 0.9.2 binary.

| Package | How it was inspected | Required notices present | Missing | Extra (not linked into the shipped binary) |
|---|---|---|---|---|
| macOS DMG (`imshark.app`) | Mounted read-only; `Contents/Resources/licenses`; `otool -L` (system frameworks only, no `Contents/Frameworks`, so everything else is static) | imgui, imguifiledialog, glfw3, openssl, libpcap, egl-registry, opengl-registry, `LICENSE` | none | gtest, vcpkg-cmake, vcpkg-cmake-config, vcpkg-cmake-get-vars |
| Linux tar.gz | Extracted; `share/imshark/licenses`; `strings` shows libpcap 1.10.7 and OpenSSL 3.6.5 statically linked | imgui, imguifiledialog, glfw3, openssl, libpcap, egl-registry, opengl-registry, `LICENSE` | none | gtest, zlib, bzip2, liblzma, libxml2, libxslt, pthread-stubs, xcb-util-m4, vcpkg-cmake, vcpkg-cmake-config, vcpkg-cmake-get-vars, vcpkg-make, vcpkg-tool-meson |
| Linux DEB | `ar x` and extraction of `data.tar.gz`; `usr/share/imshark/licenses` | Same set as the tar.gz | none | Same as the tar.gz |
| Linux AppImage | **Not inspected**: `unsquashfs`, `7z` and `7zz` are not installed on the macOS audit machine and `--appimage-extract` does not run on macOS. `tools/make_appimage.sh` stages `cmake --install` into the AppDir, so the ImShark and vcpkg notices are expected to equal the tar.gz. | not verified | not verified | not verified |
| Windows ZIP | Extracted; `share/imshark/licenses` and `bin/` | imgui, imguifiledialog, glfw3 (for `glfw3.dll`), openssl (for `libcrypto-3-x64.dll`), opengl, egl-registry, opengl-registry, `LICENSE` | none for vcpkg libraries | gtest, vcpkg-cmake, vcpkg-cmake-config, vcpkg-cmake-get-vars |

Findings:

1. **No required notice was missing from 0.9.2.** Every library linked into or shipped with the binaries has its notice.
2. **Extra notices:** `gtest` is shipped in every package although GoogleTest is test-only, and the Linux packages carry build-tool and transitive ports (zlib, bzip2, liblzma, libxml2, libxslt, xcb helpers, `vcpkg-*`). They are harmless but misleading. The install rule globs every installed port, so the list is whatever vcpkg happened to install.
3. **`stb` after 0.9.2:** the same glob picks up `share/stb/copyright`, so the next release ships `stb.txt` without a rule change.
4. **Windows runtime:** the ZIP contains the Microsoft Visual C++ runtime DLLs (`vcruntime140*.dll`, `msvcp140*.dll`, `concrt140.dll`). They are redistributable under Microsoft's distributable-code terms and have no notice file in the package. They are not third-party open-source notices, but the maintainer should confirm that the terms are acceptable for a GPL-3.0 download.
5. **Not shipped, correctly:** Npcap (its licence forbids redistribution without a separate agreement; the Windows package has no live capture), and system libraries on Linux (GL, X11).
6. **Dear ImGui bundles** `stb_truetype`, `stb_rect_pack` and `stb_textedit` (public domain or MIT, each with its terms in its own header). The `imgui` notice does not repeat them; since they are public domain or MIT-alternative and the headers travel with the library source, this was left as is.
7. **DEB:** the package has no `/usr/share/doc/imshark/copyright` file; the licence is under `/usr/share/imshark`. Debian policy expects the former; the project is not packaged for Debian proper, so this is only a note.
8. **AppImage:** linuxdeploy copies system shared libraries into the image without their licence files. This was not checked here, and should be looked at when the AppImage can be extracted on Linux.

### Fix applied after the audit

The install rule in `CMakeLists.txt` now skips the `gtest` notice and the `vcpkg-*` build-script ports. Verified with `cmake --preset debug`, `cmake --build --preset debug` and `cmake --install build-debug --prefix <scratch>` on macOS arm64 (Debug, ASan/UBSan): `imshark.app/Contents/Resources/licenses` holds exactly `egl-registry`, `glfw3`, `imgui`, `imguifiledialog`, `libpcap`, `opengl-registry`, `openssl` and `stb`, `codesign --verify --deep --strict` passes and the installed binary runs `--version`. Before the change the same install also shipped `gtest`, `vcpkg-cmake`, `vcpkg-cmake-config` and `vcpkg-cmake-get-vars`, and `stb.txt` was already present. The Linux extras (zlib, bzip2, liblzma, libxml2, libxslt, xcb helpers) come from the Linux vcpkg dependency closure and could not be rebuilt here; check the Linux `licenses` directory of the next release candidate and decide whether to prune them.

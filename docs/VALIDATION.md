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

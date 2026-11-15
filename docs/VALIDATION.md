# Validation record — 8–9 October 2026

For the current Windows capture checks and their remaining driver/UAC limits, see the [Windows capture validation record](WINDOWS_CAPTURE_VALIDATION.md). The historical results below are unchanged.

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

## Windows clean machine checklist, ImShark 1.0.0

Run of the [Windows clean machine checklist](RELEASING.md#9-windows-clean-machine-checklist) on 15 November 2026. **The checklist asks for an x86_64 machine; this run used an Arm64 virtual machine, where the x86_64 package runs under Windows' x64 emulation. It does not close the 1.0 gate item** and has to be repeated on x86_64.

| | |
|---|---|
| Package | [`imshark-1.0.0-windows-x86_64.zip`](https://github.com/Zaryob/imshark/releases/tag/v1.0.0), SHA-256 `5e53514f1f87e568a776a60a295db0d033dabaf3b27b403ab147a75e86a75ccd` |
| Windows | Windows 11 Home 26H2, build 26300.9457, Arm64, Turkish (tr-TR), installed 11 November 2026 by VirtualBox unattended setup |
| Machine | VirtualBox 7.2.22 r175245 virtual machine on an Apple Silicon Mac (macOS 27.2): 5 virtual CPUs, 8 GB, EFI, VBoxSVGA with the Guest Additions 7.2.22 WDDM driver, 1024×768, 3D acceleration off unless stated |
| Tested by | Scripted run on Suleyman Poyraz's machine. Commands ran through VirtualBox guest control. The GUI steps used synthetic mouse and keyboard input in the desktop session and were read from screenshots taken inside the guest. |

State before the test: no Visual Studio, vcpkg or ImShark; no `vcruntime140*.dll` or `msvcp140.dll` in `System32`, `SysWOW64` or `SysArm32`; the installed programs were Microsoft Edge, Edge Update, WebView2 Runtime, OneDrive and the VirtualBox Guest Additions.

Two things were added to the machine during the run, so it was no longer untouched for the items after them:

- The Red Hat VirtIO network driver (`NetKVM`, virtio-win 0.1.302). VirtualBox's default USB network adapter never started in this guest (device error 10), and Windows on Arm has no built-in driver for the other adapter types. Added before item 1.
- Microsoft's *OpenCL, OpenGL and Vulkan Compatibility Pack* (`Microsoft.D3DMappingLayers` 1.2608.3.0, from the Microsoft Store). Added after item 4 failed, to run items 4 to 8.

| # | Checklist item | Result | What was seen |
|---|---|---|---|
| 1 | Download with a browser; digest matches | passed | Edge downloaded the ZIP without a warning. `Get-FileHash` gave `5e53514f…75ccd`, equal to the line in `SHA256SUMS.txt`. `SHA256SUMS.txt` itself was fetched with `Invoke-WebRequest`, because Edge shows text files instead of saving them. |
| 2 | Extract to a path with a space and a non-ASCII character | passed | Extracted with the Explorer ZIP handler to `C:\ImShark Test\İndirilenler\imshark`: 23 files, 11,541,290 bytes. The Mark of the Web (`ZoneId=3`) was carried over to `imshark.exe`. |
| 3 | `bin\imshark.exe --version` | passed | Printed `imshark 1.0.0 (v1.0.0)`, exit code 0, no missing DLL. The system directories had no Visual C++ runtime, so the DLLs in the package's `bin` folder were the ones used. |
| 4 | Double-click: window, logo, welcome screen, icons; SmartScreen | **failed as shipped**; passed with the OpenGL pack | As shipped the program exited at once with code 1 and showed nothing. Its error output was `GLFW error 65542: WGL: The driver does not appear to support OpenGL`. This guest has no OpenGL driver that an x64 program can load; turning VirtualBox 3D acceleration on did not change it. With the compatibility pack installed the window opened (`openglon12.dll` loaded) with the logo, the welcome screen and the ImShark icon on the title bar and the taskbar. A console window opened next to it. SmartScreen: no warning while online. Offline it showed "SmartScreen can't be reached right now", publisher "Unknown publisher", application `imshark.exe`, with **Run** and **Don't run**. |
| 5 | Open `sample.pcap` through **File > Open** and by drag and drop | passed (with the OpenGL pack) | Both loaded 16 packets; the title became `sample.pcap (16 packets) - ImShark`. Selecting packet 10 filled the details tree and the hex view. `imshark.exe <path>` opened the file too. |
| 6 | Apply `tcp`, clear it, switch themes | passed (with the OpenGL pack) | `tcp` left packets 7 to 12 and 16; the clear button brought back all 16. **View > Light Theme** and **Dark Theme** both applied. |
| 7 | Close and reopen: size, position, recent files | **partly failed** (with the OpenGL pack) | Recent files were remembered in **File > Open Recent** and on the welcome screen. A window moved to 120,40 at 860×640 came back in the same place. But after the first run, which opens at the default size on this 1024×768 screen, the second start put the window at 0,0 by its client area: the title bar was above the top of the screen and could not be reached with the mouse. |
| 8 | Start live capture shows the expected guidance | passed (with the OpenGL pack) | The **Capture** entries and the toolbar buttons are disabled. The tooltip says "Live capture is not available in this build (built without libpcap / Npcap; configure with IMSHARK_LIVE_CAPTURE=ON)". |
| 9 | Licence notices under `share\imshark\licenses` | passed | 10 files, 21,518 bytes: `egl-registry`, `glfw3`, `imgui`, `imguifiledialog`, `opengl-registry`, `opengl`, `openssl`, `pcre2`, `pcre2-LICENCE.md`, `stb`; plus `share\imshark\LICENSE`. |
| 10 | Delete the extracted folder; nothing else left behind | passed | After deleting the folder and the downloads, the only ImShark file left was `%APPDATA%\imshark\settings.ini` (241 bytes). Nothing named `imshark` was found elsewhere in the profile, in `C:\ProgramData`, in `%TEMP%` or under `HKCU\Software`. Traces that Windows keeps on its own (for example Recent shortcuts) were not searched. |
| 11 | Record the result | done | This section. |

After the run the settings file, the helper files of the test and the scheduled task that drove the desktop session were removed. The VirtIO driver and the OpenGL pack stayed installed. The VirtualBox snapshot `pre-imshark-check` holds the machine as it was before the test.

Findings to file as issues ([RELEASING.md](RELEASING.md#9-windows-clean-machine-checklist) says failures are recorded as issues):

1. **No window without an OpenGL 3.2 driver, and no message.** The 1.0.0 package exits with code 1 silently. A user who double-clicks it sees nothing. A fix is on the branch `feature/windows-d3d11-fallback` (see below).
2. **Title bar off screen on the second start** when the saved window is as large as the work area (seen at 1024×768). The saved position is that of the client area, and the restore step moves it to the top of the work area without leaving room for the title bar.
3. **A console window opens with the GUI** when `imshark.exe` is started from Explorer.
4. **The file dialog shows `?` for the Turkish letters `ğ` and `ı`** in folder names (`Müzi?im`, `Videolar?m`); `ü` is shown. Opening files under `İndirilenler` worked.
5. **The file dialog starts with the `.pcapng` type**, so a `.pcap` file is hidden until the type box is changed.

### Follow-up build with a Direct3D 11 fallback

The branch `feature/windows-d3d11-fallback` ([pull request 16](https://github.com/Zaryob/imshark/pull/16)) adds a Direct3D 11 backend that is used when OpenGL 3.2 is missing: first on the graphics card, then on WARP, the software rasterizer that ships with Windows. Its Windows ZIP came from [CI run 43684670123](https://github.com/Zaryob/imshark/actions/runs/43684670123), which built the renderer code of that pull request as commit `c4fa8b5`, before the branch was rebased (`imshark-1.0.0-win64.zip`, SHA-256 `dea61f2e0079551d58f250a471cf619adb0311fa20e4fe34f683f190895a27d4`) and was tested in the same virtual machine, before the OpenGL pack was installed unless stated:

| Case | Result |
|---|---|
| 3D acceleration off, no OpenGL | The window opened. Error output: `OpenGL 3.2 is not available; trying Direct3D 11`, then `Using Direct3D 11, flip model, 1028x720`. `d3d10warp.dll` was loaded, so the frames were drawn in software. |
| 3D acceleration on, no OpenGL | The window opened: `Using Direct3D 11 (software), flip model`. |
| `IMSHARK_RENDERER=software` | The window opened on WARP. |
| `IMSHARK_RENDERER=opengl` | A message box: "ImShark cannot open its window: OpenGL 3.2 is not available." with advice, instead of a silent exit. |
| GUI items 5 to 8, 3D acceleration off | **File > Open**, drag and drop, selecting a packet, the `tcp` filter and its clearing, both themes, the live capture tooltip, resizing, and size, position and recent files after reopening all worked. |
| After the OpenGL pack was installed | The build chose OpenGL again (`openglon12.dll` loaded, no fallback message). |

The first build of the branch (its first commit) used the older blit-model swap chain. With 3D acceleration off its window stayed blank white, although it drew correctly with 3D acceleration on. Its second commit switched to the flip model, which fixed it.

Not covered: an x86_64 machine, a real graphics card, Windows 10, and high-DPI or multi-monitor setups.

# Building ImShark

ImShark uses C++20, CMake 3.21 or newer, Ninja and vcpkg manifest mode. Set `VCPKG_ROOT` to a bootstrapped vcpkg checkout before configuring. Run commands from the repository root.

## Platform prerequisites

vcpkg builds the C/C++ libraries: Dear ImGui with the GLFW/OpenGL3 backends, ImGuiFileDialog, GLFW, GoogleTest, OpenSSL and libpcap on supported platforms. The operating system still supplies the compiler, window-system development headers and graphics driver.

### macOS

Install the Xcode command-line tools, then CMake, Ninja and pkg-config (for example through Homebrew):

```sh
xcode-select --install
brew install cmake ninja pkg-config autoconf autoconf-archive automake libtool
```

### Linux (Ubuntu/Debian)

These are build tools and the native X11/OpenGL development requirements used by GLFW; the GLFW, TLS, capture and test libraries themselves come from vcpkg:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git curl zip unzip tar pkg-config ca-certificates \
    autoconf autoconf-archive automake libtool libltdl-dev bison flex \
    libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev \
    libwayland-dev wayland-protocols libgl1-mesa-dev libglu1-mesa-dev
```

A desktop session with OpenGL 3.2 support is needed to run the application. Headless verification uses Xvfb and Mesa; see [Docker verification](#linux-docker-verification).

### Windows

Install Visual Studio 2022 with the **Desktop development with C++** workload, Git, CMake and Ninja. Run the build from a Visual Studio developer PowerShell so the MSVC environment is available. TLS decryption is enabled by default. Live capture is disabled by default; the normal Windows build does not need the Npcap SDK.

## Prepare vcpkg

Use an existing vcpkg installation or create one outside the source tree:

```sh
# macOS / Linux
git clone https://github.com/microsoft/vcpkg.git "$HOME/vcpkg"
"$HOME/vcpkg/bootstrap-vcpkg.sh" -disableMetrics
export VCPKG_ROOT="$HOME/vcpkg"
```

```powershell
# Windows
git clone https://github.com/microsoft/vcpkg.git "$env:USERPROFILE/vcpkg"
& "$env:USERPROFILE/vcpkg/bootstrap-vcpkg.bat" -disableMetrics
$env:VCPKG_ROOT = "$env:USERPROFILE/vcpkg"
```

The manifest's `builtin-baseline` pins registry ports. The current baseline provides Dear ImGui **1.92.9b** (vcpkg port `1.92.9`), GLFW **3.5.1**, OpenSSL **3.6.5**, libpcap **1.10.7** and GoogleTest **1.18.0**. ImGuiFileDialog is provided by a versioned local overlay under `vcpkg-ports/`. Configure downloads and builds the selected dependencies automatically. Network access is required for the first build; vcpkg's binary cache can speed up subsequent builds.

Dear ImGui is pinned to the current port selected by the manifest baseline, rather than downloaded from a moving branch on every configure. Updating dependencies means deliberately updating the baseline/overlay and validating the new build and tests together. See [vcpkg.json](../vcpkg.json) and [vcpkg-configuration.json](../vcpkg-configuration.json) for the authoritative versions and registry configuration.

## Configure, build and test

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

| Preset | Build directory | Purpose |
|---|---|---|
| `default` | `build/` | Release application, tools and tests with vcpkg |
| `debug` | `build-debug/` | Debug application and tests |
| `minimal` | `build-minimal/` | TLS decryption and live capture disabled; verifies their fallback APIs |
| `vcpkg` | `build/` | Compatibility alias for `default` |

Build and test presets have the same names. Run one CTest suite at a time, including across build directories: some tests share temporary files. Do not use `ctest -j` for this suite. An explicit sanitizer build with GCC or Clang is:

```sh
cmake --preset debug -DIMSHARK_SANITIZE=ON
cmake --build --preset debug
ctest --preset debug
```

ASan and UBSan instrument the application code, including the core. The `IMSHARK_SANITIZE` combination is not supported with MSVC. Use a fresh build directory when changing compilers, vcpkg triplets or toolchain settings.

### CMake options

| Option | Default | Effect |
|---|---|---|
| `IMSHARK_BUILD_TESTS` | `ON` | Build GoogleTest and documentation/regression checks |
| `IMSHARK_BUILD_TOOLS` | `ON` | Build the headless `imshark_dump` tool |
| `IMSHARK_BUILD_BENCH` | `OFF` | Build `bench_driver` |
| `IMSHARK_TLS_DECRYPT` | `ON` | Use OpenSSL 3 libcrypto for TLS/DTLS decryption |
| `IMSHARK_LIVE_CAPTURE` | `ON` on Unix, `OFF` on Windows | Use libpcap/Npcap for live capture |
| `IMSHARK_SANITIZE` | `OFF` | GCC/Clang AddressSanitizer and UndefinedBehaviorSanitizer |
| `IMSHARK_COVERAGE` | `OFF` | Clang source-based coverage |

An enabled dependency must be available; configure should fail instead of silently skipping tests or required capabilities. Disable an optional feature explicitly to build its fallback API.

## Run

```sh
# Linux
./build/imshark tests/data/sample.pcap
./build/imshark --version

# macOS
./build/imshark.app/Contents/MacOS/imshark tests/data/sample.pcap
./build/imshark.app/Contents/MacOS/imshark --version
```

```powershell
# Windows (Ninja)
.\build\imshark.exe tests/data/sample.pcap
.\build\imshark.exe --version
```

`--version` works without a display server. Running the full application requires a working graphics context. `imshark_dump` is a separate headless tool.

### Live capture privileges

Offline analysis needs no capture privileges. On macOS, live capture needs access to `/dev/bpf*`. On Linux, grant the built executable the capabilities appropriate for your capture environment, for example:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip ./build/imshark
```

Rebuilding replaces the executable and can remove these capabilities. Windows live capture is an advanced configuration: install the Npcap runtime driver and obtain its SDK, enable `IMSHARK_LIVE_CAPTURE` and set `NPCAP_SDK_DIR` to the SDK directory. The vcpkg libpcap Windows port's default null backend is not a replacement for Npcap capture support.

## Linux Docker verification

The repository's Docker build installs its own toolchain and display headers, builds dependencies through the same vcpkg manifest, builds the Release application and runs the test suite:

```sh
docker build --target verify -t imshark-linux-verify .
docker run --rm --init --network none imshark-linux-verify
```

The container repeats CTest, then opens the checked-in sample capture in the real GLFW/OpenGL application under Xvfb with Mesa software rendering and closes it gracefully. This checks a Linux GUI startup and sample-file path as well as the headless core; it does not exercise a physical capture device or a hardware graphics driver.

To retain smoke-test artifacts:

```sh
mkdir -p artifacts/linux
docker run --rm --init --network none \
    -v "$PWD/artifacts/linux:/artifacts" \
    -e SMOKE_ARTIFACT_DIR=/artifacts imshark-linux-verify
```

Verify the generated DEB separately in a fresh Ubuntu image containing only
the package, its declared runtime dependencies and the display-test tools:

```sh
docker build --target package-verify -t imshark-linux-package .
docker run --rm --init --network none imshark-linux-package
```

This stage has no compiler, vcpkg checkout or application build tree. It checks
the installed `/usr/bin/imshark`, including the native X11/OpenGL libraries GLFW
loads dynamically and which Debian's automatic dependency scan cannot detect.

## Packaging

After a successful Release build, run CPack from the build directory:

```sh
cd build
cpack -C Release
```

CMake configures a macOS `.dmg`, Linux `.tar.gz`/`.deb`, or Windows `.zip`. `tools/make_appimage.sh` uses a separately supplied `linuxdeploy` for Linux AppImages. The tag-triggered release workflow builds/tests packages and creates a draft release; a local build does not publish anything.

The install step copies dependency copyright notices, including transitive vcpkg dependencies. macOS keeps these notices inside the `.app` resources; Linux/Windows use `share/imshark/licenses`. The AppImage helper stages the same install tree. Windows packages include the runtime DLLs found by CMake; macOS installation uses `fixup_bundle` and ad hoc signing. Developer ID signing and notarization are not configured. Test the resulting package on a clean target system before publishing.

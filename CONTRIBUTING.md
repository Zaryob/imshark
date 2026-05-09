# Contributing to ImShark

First off, thank you for considering contributing to ImShark! ImShark is a lightweight, high-performance packet analysis tool, and community contributions are highly appreciated.

## Types of Contributions

1. **Bug Reports:** If you find a bug, please open an issue. Provide the OS, ImShark version, a description of the bug, and ideally a small PCAP file that reproduces the issue.
2. **Pull Requests (Features & Fixes):** Enhancements to the core parser, UI improvements, or bug fixes.
3. **Protocol Additions:** Adding new dissectors for network protocols. Please refer to [docs/DISSECTORS.md](docs/DISSECTORS.md) for a comprehensive guide on writing dissectors.

## Development Environment Setup

ImShark is written in C++20 and built with CMake (3.21 or newer). It uses Dear ImGui (vendored in `third_party/`) with
GLFW/OpenGL3 for the window, GoogleTest for the tests, and, optionally, libpcap (live capture) and OpenSSL 3 (TLS
decryption). When an optional library is missing the build still succeeds and the feature reports that it is not
available in this build. These are the packages the CI workflow installs.

### macOS
```bash
brew install cmake pkg-config glfw googletest openssl@3
```
(libpcap comes with the macOS SDK; `/opt/homebrew/opt/openssl@3` is found automatically.)

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libglfw3-dev libgl1-mesa-dev libgtest-dev libpcap-dev libssl-dev
```

### Windows
Install Visual Studio with the "Desktop development with C++" workload, CMake and [vcpkg](https://vcpkg.io/). GLFW and
GoogleTest come from the vcpkg manifest (`vcpkg.json`):
```bash
cmake --preset vcpkg
cmake --build --preset vcpkg --config Release
```
The CI builds Windows with `-DIMSHARK_LIVE_CAPTURE=OFF -DIMSHARK_TLS_DECRYPT=OFF` (no Npcap SDK or OpenSSL on the
runner). The Windows build has not been exercised on real hardware by the maintainers.

## Building and Testing

`CMakePresets.json` has two configure presets (both Release): `default` (system packages, build directory `build/`) and
`vcpkg` (dependencies from vcpkg, needs `VCPKG_ROOT`, build directory `build-vcpkg/`):

```bash
cmake --preset default && cmake --build --preset default
```

For development a Debug build with the tests is usual:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure      # run serially: some tests share temporary files
```

Before you commit parser or dissector changes, also run the suite under AddressSanitizer and UndefinedBehaviorSanitizer.
The mutation and truncation sweeps in the tests only prove memory safety when they run instrumented:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIMSHARK_SANITIZE=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

Source based code coverage (needs clang and `llvm-cov`; it configures its own `build-cov/`):

```bash
tools/coverage.sh           # per-file summary table
tools/coverage.sh --html    # also writes build-cov/coverage-html/index.html
```

### Corpus rules

`tests/corpus/` holds small **synthetic** captures made by `tools/make_corpus.py` (their expectations are written there by
construction, not copied from ImShark's output) and `manifest.json`, which describes every file with its source, SHA-256,
format, link types, packet count and expected protocols. Rules:

- Do not commit real captures or large files; the repository keeps only the small synthetic ones. A real capture is
  described in the manifest as kind `real` with its source URL and SHA-256, and found at test time through
  `IMSHARK_CORPUS_DIR`. The tests never download anything.
- Check the licence of a real capture before you name it in the manifest, and never add a capture that contains private
  traffic.
- Regenerate the manifest with the script (`python3 tools/make_corpus.py`, add `--real-dir DIR` to record real captures
  you have) rather than editing it by hand, and check in the result together with the change that needs it.

Real sample captures are optional: set `IMSHARK_CORPUS_DIR` to a directory holding the files listed in
`tests/corpus/manifest.json` (the tests never download anything and skip those checks when it is not set).
`IMSHARK_BUILD_BENCH=ON` additionally builds the benchmark driver (`tools/benchmark.py`).

## Code Style

The repository has a `.clang-format` file in the root. Format the code you write with it when `clang-format` is
available, but do not reformat whole existing files in an unrelated change; match the surrounding code (naming,
comment density, one dissector per file, explicit source lists in `core/CMakeLists.txt` and `tests/CMakeLists.txt`).

## Commit Messages

Recent history uses one imperative sentence for the subject that says what the change does, followed by a tag in
parentheses naming the ROADMAP item or kind of change, for example
`Clamp SCTP chunk lengths to the packet and test the CRC independently (v1.1 fix)`. Older commits use
`feat(scope): ...` / `docs: ...`. Either is fine; keep the first line short and imperative, and use the body for a
bullet list of what changed and why. Split a delivery into small commits that each build and pass their tests.

## Delivery rules for features and protocols

`ROADMAP.md` ("Ortak teslim kuralları", in Turkish) is the binding list. In short: the three kinds of test; a number or
field is verified by something other than the code under test (an RFC vector, an independent Python computation, the
`openssl` command line); cross-packet state is decided in the load pass and only read in Replay; `sizeof(packet::PacketInfo)`
stays within the 336-byte test bound; filter fields go into `core/src/filter/fields.cpp`; and every delivery updates
`docs/KNOWN_ISSUES.md`, the README feature list and `docs/SUPPORT_MATRIX.md`. Tick a ROADMAP item only when the code meets
all of it, and say in an italic note what is still missing otherwise. `docs/USER_GUIDE.md` and its generated filter reference
(`docs/FILTER_FIELDS.md`) are checked by tests: see the `Docs` tests in `tests/test_docs.cpp`.

## Packaging and Releases

`cpack -C Release` in the build directory produces the platform package: a `.dmg` on macOS (DragNDrop, `imshark.app` at
the top of the image), `.tar.gz` and `.deb` on Linux, `.zip` on Windows. `.github/workflows/release.yml` runs the build,
the tests and `cpack` for a pushed `v*` tag and attaches those files to the GitHub release; it refuses a tag that differs
from the `project(imshark VERSION ...)` in `CMakeLists.txt`. Things that are **not** done: an AppImage is not built in CI
(`tools/make_appimage.sh` is a manual helper that needs a linuxdeploy you provide), the packages do not bundle GLFW or
OpenSSL (the macOS app links the Homebrew libraries), nothing is signed or notarized, and the workflow has not been run
on GitHub yet. `tools/make_dmg.sh` makes a DMG by hand from the build tree.

## Benchmark

`python3 tools/benchmark.py` builds `bench_driver` (CMake option `IMSHARK_BUILD_BENCH`, off by default), generates a
synthetic capture in a temporary directory, loads it the way the application does, runs one filter pass and prints
load time, filter time and peak RSS; the capture is deleted afterwards. Never commit capture files. The measured
numbers and the machine they were taken on are in `ROADMAP.md` (v1.0, performance reference).

## Pre-Pull Request Checklist

Before submitting a Pull Request, please ensure you have completed the following:

- [ ] The project builds on your machine and all tests pass (`ctest`).
- [ ] The tests also pass with `-DIMSHARK_SANITIZE=ON`.
- [ ] A new feature or protocol has tests of the three kinds described in [docs/DISSECTORS.md](docs/DISSECTORS.md)
      (optional real captures, hand-built messages with an independent oracle, truncation/mutation sweep).
- [ ] `docs/KNOWN_ISSUES.md`, `docs/SUPPORT_MATRIX.md`, `docs/PROTOCOLS.md` and the README feature list say what the code
      does and does not do.
- [ ] You read the "Ortak teslim kuralları" (common delivery rules) in `ROADMAP.md`.

Thank you for contributing!

# Contributing to ImShark

First off, thank you for considering contributing to ImShark! ImShark is a lightweight, high-performance packet analysis tool, and community contributions are highly appreciated.

## Types of Contributions

1. **Bug Reports:** If you find a bug, please open an issue. Provide the OS, ImShark version, a description of the bug, and ideally a small PCAP file that reproduces the issue.
2. **Pull Requests (Features & Fixes):** Enhancements to the core parser, UI improvements, or bug fixes.
3. **Protocol Additions:** Adding new dissectors for network protocols. Please refer to [docs/DISSECTORS.md](docs/DISSECTORS.md) for a comprehensive guide on writing dissectors.

## Development Environment Setup

ImShark is built with C++17 and CMake. It uses Dear ImGui for the UI and GLFW/OpenGL3 for rendering.

### macOS
```bash
brew install cmake ninja vcpkg
# Install GLFW using vcpkg or brew
brew install glfw
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build pkg-config
sudo apt-get install libglfw3-dev libgl1-mesa-dev
```

### Windows
1. Install [Visual Studio](https://visualstudio.microsoft.com/) with the "Desktop development with C++" workload.
2. Install [CMake](https://cmake.org/download/).
3. Use [vcpkg](https://vcpkg.io/) to install GLFW: `vcpkg install glfw3:x64-windows`.

## Building and Testing

ImShark uses standard CMake build workflows. We recommend using Ninja for faster builds.

```bash
# Configure the project
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug

# Build the targets
cmake --build build

# Run tests
cd build
ctest --output-on-failure
```

## Code Style

ImShark uses `clang-format` to enforce a consistent coding style.
Before committing, format your code using the provided `.clang-format` file in the repository root.

```bash
# Example formatting a file
clang-format -i path/to/your/file.cpp
```

## Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature").
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
- Limit the first line to 72 characters or less.
- Reference issues and pull requests liberally after the first line.

## Pre-Pull Request Checklist

Before submitting a Pull Request, please ensure you have completed the following:

- [ ] Code is formatted with `clang-format`.
- [ ] The project builds successfully on your local machine.
- [ ] All tests pass (`ctest`).
- [ ] Memory safety has been verified by running the tests with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) enabled.
- [ ] If you added a new feature or protocol, you have included corresponding tests.
- [ ] Read and adhere to the Common Delivery Rules outlined in `ROADMAP.md`.

Thank you for contributing!

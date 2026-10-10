# Changelog

All notable changes to ImShark are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/). Detailed per-release notes, including the download table, live in [docs/releases/](docs/releases/). Procedure: [docs/RELEASING.md](docs/RELEASING.md).

Only the packages of **0.9.2** were ever published on GitHub Releases. Earlier tags exist in the repository but produced no packages; the entries below say why.

## [1.0.0] - 2026-10-10

First stable release. [Release notes](docs/releases/v1.0.0.md); what 1.0 promises to keep stable is in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

### Added
- Capture helper: live capture runs through `imshark --capture-worker`, which starts only after an explicit **Authorize and capture** click, opens the device with elevated rights and drops privileges before touching any file, instead of opening system-wide permissions. Also adds the ImShark icons and welcome-screen logo ([#8](https://github.com/Zaryob/imshark/pull/8)).
- Display filters run on a background thread with progress and cancellation, and exports keep nanosecond timestamps ([#11](https://github.com/Zaryob/imshark/pull/11)).
- Settings file format version, atomic saves, `docs/COMPATIBILITY.md` (the 1.0 stability promise) and `docs/THREAT_MODEL.md` ([#10](https://github.com/Zaryob/imshark/pull/10)).
- CodeQL and clang-tidy in CI, one warning set for all targets and an `IMSHARK_WERROR` option ([#12](https://github.com/Zaryob/imshark/pull/12)).
- libFuzzer harnesses with seed corpora, replayed as tests in every build and run in CI, plus `docs/FUZZING.md` ([#13](https://github.com/Zaryob/imshark/pull/13)).
- `CHANGELOG.md`, `docs/RELEASING.md`, an updated user guide, a third-party licence audit of the 0.9.2 packages (`docs/VALIDATION.md`) and the logo licence (CC0 1.0) ([#14](https://github.com/Zaryob/imshark/pull/14)).

### Changed
- The macOS bundle identifier changes from `com.imshark.app` (0.9.1 and 0.9.2) to `io.github.zaryob.imshark` ([#8](https://github.com/Zaryob/imshark/pull/8)); macOS treats the 1.0 app as a different application for per-app permissions.
- Regular expressions in display filters and coloring rules are evaluated with PCRE2 (Perl-compatible syntax, like Wireshark) under match, depth and heap limits instead of `std::regex`; a pattern that hits a limit counts as no match and is reported in the status bar ([#15](https://github.com/Zaryob/imshark/pull/15)).
- Decompression of `.gz` captures has an output limit and an expansion-ratio guard, and temporary files are created exclusively with random names in a private directory ([#9](https://github.com/Zaryob/imshark/pull/9)).

### Fixed
- A heavy regular expression in a display filter no longer terminates the application ([#11](https://github.com/Zaryob/imshark/pull/11)) or runs for seconds through catastrophic backtracking ([#15](https://github.com/Zaryob/imshark/pull/15)).
- Parser bugs found by fuzzing: a DNS-over-TCP over-read, a length underflow after the FCS, BGP and HTTP/2 nodes reaching past their payload, and quadratic growth of the info column ([#13](https://github.com/Zaryob/imshark/pull/13)).
- Checked integer parsing for HTTP status and X.509 years and other findings from the new static analysis ([#12](https://github.com/Zaryob/imshark/pull/12)).

## [0.9.2] - 2026-10-09

First published 0.9 release; contains everything planned for 0.9.0 and 0.9.1.

### Changed
- The Docker images used by the Linux GUI release check are pulled through `mirror.gcr.io` instead of Docker Hub.

## 0.9.1 - 2026-10-09 (not published)

The release run stopped before building anything: Docker Hub rate-limited the Linux GUI check and then timed out. The tag stays in the repository, and its changes shipped in 0.9.2.

### Added
- Welcome screen with Open / Start live capture, recent files and a drop hint.
- Toolbar (View > Toolbar) with shortcut tooltips; status bar shows displayed/total and selected packets.
- A draggable list/details splitter, and window size and position remembered between sessions.
- 43 headless UI interaction tests; CI runs on every push and pull request, including Windows.
- Issue forms, pull request template, Dependabot configuration and `SECURITY.md`.

### Changed
- Refreshed dark and light themes with one accent colour; coloring rules stay readable in the dark theme.
- README is English by default, with a Turkish translation in `README.tr.md`.

### Fixed
- The macOS app and DMG carry `com.imshark.app` as `CFBundleIdentifier` (it was empty).
- MSVC test build failure that stopped 0.9.0; text fixtures are checked out with LF on every platform.

## 0.9.0 - 2026-10-09 (not published)

No packages: the Windows test build failed. Its changes shipped in 0.9.2.

### Added
- Database session table for PostgreSQL and MySQL with strict memory bounds.
- PostgreSQL extended query decoding (Parse, Bind, Describe, Execute, Close), typed parameters and DataRow values, COPY data.
- MySQL result set and prepared statement decoding.
- RPCSEC_GSS handling for ONC RPC / NFS.
- Filter fields `pgsql.statement`, `pgsql.value`, `pgsql.count`, `mysql.value`, `mysql.statement_id`.

## 0.8.x - 2026-10-08 to 2026-10-09 (not published)

0.8.0, 0.8.1 and 0.8.2 were tagged while the release pipeline was being brought up; none of them published packages. 0.8.1 fixed the MSVC build and 0.8.2 fixed an AddressSanitizer failure in the SCTP test fixtures and the vcpkg cache keys. All their changes shipped in 0.9.2.

### Added
- Pinned vcpkg manifest for all C/C++ dependencies (Dear ImGui and its GLFW/OpenGL3 backends); vendored copies removed.
- `--help`, `--version`, argument validation and capture-aware window titles.
- Release, debug/sanitizer and minimal build presets.
- Tag-triggered release workflow that publishes tested packages with SHA-256 checksums.

### Fixed
- Capture exports can no longer overwrite their input; clipboard selections are bounded; capture-loading and settings errors are reported cleanly.
- Portable NFS timestamps, GCC diagnostics, MSVC packet initialization, SCTP test payload lifetime.

[0.9.2]: https://github.com/Zaryob/imshark/releases/tag/v0.9.2

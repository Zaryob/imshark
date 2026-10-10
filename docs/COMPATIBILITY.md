# Compatibility Promise

This document states what ImShark 1.0 and every later 1.x release keep stable, and what they do not. ImShark follows
[Semantic Versioning](https://semver.org/) for the surfaces listed under "Stable". Anything not listed there, or listed
under "Not stable", may change in any release.

Version rule in short:

- **Patch** (1.0.x): bug fixes only. No stable surface changes, except to correct a documented behaviour that was wrong.
- **Minor** (1.x.0): additions (new fields, new flags, new export columns where allowed below, new protocols). Deprecations
  start here. Nothing stable is removed.
- **Major** (2.0.0): the only place a stable surface may be removed or changed incompatibly.

Release notes (`docs/releases/`) name every deprecation, every new settings version and every change of what a field
reports.

## Stable

### 1. Settings file

Location: `settings.ini` in the per-user configuration directory (`%APPDATA%\imshark` on Windows,
`~/Library/Application Support/imshark` on macOS, `$XDG_CONFIG_HOME/imshark` or `~/.config/imshark` elsewhere;
`defaultSettingsPath()` in `src/ui/settings.cpp`). The format is a text file of `key=value` lines; the first line written
is `settings_version=<n>`. The current version is 1 (`ui::kSettingsVersion`).

Guarantees:

- **Newer ImShark reads older files.** A file without `settings_version` is version 0 (every file written before the key
  existed). It is migrated on the next save; the 0 to 1 migration changes no key, it only adds `settings_version`. Every
  later version bump ships with a migration that is applied on load, and a test that loads a file of each earlier version.
- **Older ImShark does not damage newer files.** A file whose version is higher than the running program supports is read
  for the keys the program knows, shown once as a status message ("Settings were written by a newer ImShark..."), and is
  **never rewritten**. Preferences changed in that session are not saved; the newer program's data stays as it was.
- **Unreadable files are not destroyed.** A file that cannot be read as settings (NUL bytes, over 1 MiB, text with no known
  key, a malformed `settings_version`) is copied to `settings.ini.bak-<UTC timestamp>` before it is replaced by defaults.
  If the copy cannot be made, nothing is overwritten.
- **Saves are atomic.** The new content is written to a temporary file in the same directory and renamed over the old
  one. A crash or a full disk leaves the previous file intact.
- **Bad values fall back to the default** for that key; they never stop the program from starting.
- **Unknown keys** are ignored on load and **dropped** when a current or older file is saved (they are only kept in files
  of a newer version, which are not rewritten at all).
- Keys inside a version are not renamed or repurposed. A key is added or retired only with a version bump.
- Not covered: manual edits that break the syntax, and the on-disk order of the lines.

Tests: `tests/test_settings.cpp` (`SettingsVersion.*` and the older `Settings.*` cases).

### 2. Display filter language and field names

- **Syntax.** The operators and forms described in [USER_GUIDE.md](USER_GUIDE.md#display-filters) (`&&` `||` `!`,
  `==` `!=` `<` `>` `<=` `>=` and their word forms, `contains`, `matches`, `in {...}` sets and ranges, CIDR networks,
  bare protocol names) keep their meaning. A filter that is valid and means X in 1.0 is valid and means X in any 1.x.
  Extensions (new operators) may be added in a minor release.
- **Field names.** Every name in [FILTER_FIELDS.md](FILTER_FIELDS.md), including `_ws.col.info` and `_ws.col.protocol`,
  is stable: in 1.x it is not removed, renamed, or given a different type. The reference is generated from the field
  table, so it is always the list the running build accepts.
- **Field values.** A field keeps reporting the same quantity in the same unit. A fix that makes a field report what its
  description always said is a bug fix (patch release, named in the release notes). Fields may start matching more packets
  when a dissector learns a protocol.
- **Adding fields** is allowed in any minor release.
- **Deprecation of a field.** A field is deprecated in a minor release and removed no earlier than 2.0. If a field must be
  renamed during 1.x, the old name stays accepted for at least one further minor release as a second entry with the
  same extractor (there is no alias mechanism in `core/src/filter` today: the field table is a flat list of
  `FieldDef`, so the old name is simply kept as another entry), and the release notes name both.
- Regular expression syntax for `matches` is the one the build documents; flags such as `(?i)` are stable.

What enforces it: `FilterSnapshot.FieldTableAndValuesAreUnchanged` (`tests/test_filter_snapshot.cpp`) compares every
field's name, type and description, and the values it yields on the sample and corpus captures, with
`tests/data/filter_fields.snapshot`. Removing or retyping a field fails that test, and the diff of the snapshot file makes
the change visible in review. `Docs.EveryFieldIsInTheReferenceAndTheReferenceIsLinked` and
`Docs.FilterReferenceIsGeneratedFromTheFieldTable` (`tests/test_docs.cpp`) keep FILTER_FIELDS.md equal to the table.
Descriptions are informational and may be reworded (that updates the snapshot, deliberately).

### 3. Command line

`imshark` (the GUI, `src/main.cpp`):

| Invocation | Behaviour | Exit code |
|---|---|---|
| `imshark` | start with no capture | 0 on normal exit |
| `imshark CAPTURE_FILE` | start and open the file | 0 on normal exit |
| `imshark -- CAPTURE_FILE` | same, for file names that start with `-` | 0 on normal exit |
| `imshark -h`, `--help` | print usage to stdout and exit (does not need a display) | 0 |
| `imshark -V`, `--version` | print `imshark <version> (<git describe>)` to stdout and exit | 0 |
| anything else (unknown flag, more than one file, flag together with a file) | `Invalid arguments.` and usage on stderr | 1 |
| window system or GL context cannot be created | message on stderr | 1 |

`imshark_dump` (`tools/imshark_dump.cpp`, built with `IMSHARK_BUILD_TOOLS`):

```
imshark_dump <capture file> [--fields name1,name2,...]
```

| Outcome | Exit code | Output |
|---|---|---|
| ok | 0 | JSON on stdout: `{"packets": [{"number": n, "protocol": "...", "fields": {"name": ["value", ...]}}]}`; a field with no value is omitted; all values are strings; a load warning goes to stderr |
| capture could not be loaded | 1 | `Load failed: ...` on stderr |
| usage error (no file, unknown flag, extra argument, `--fields` without value) or unknown field name | 2 | `Usage: ...` or `Unknown field: name` on stderr |

The default field list of `imshark_dump` may grow in a minor release; pass `--fields` for a fixed set. The flags above are
never removed in 1.x; new flags may be added. `tools/compare_tshark.py` uses this interface and has its own exit codes
(documented in its header).

What enforces it: `tests/test_cli.py` (ctest `cli_contract`) pins the exit codes, the usage text of `imshark_dump`, the
JSON shape, and the options and invalid-argument handling of `imshark`; `tests/test_compare_tshark.py` exercises
`imshark_dump` from the comparator.

### 4. Export formats

- **pcap and pcapng** (`exporter::exportPackets`): original frame bytes and link types are preserved, in capture order.
  Classic pcap needs a single link type (mixed link types need pcapng). Pcapng exports keep embedded TLS secrets as
  Decryption Secrets Blocks. Files open in Wireshark and other standard tools. Timestamp resolution is a property of the
  writer (currently microsecond for pcap); a finer resolution may be introduced in a minor release, and readers of the
  format must not depend on the digit count.
- **CSV** (`exporter::writeCsv`): UTF-8, one header line, every field quoted with `"` (quotes doubled, RFC 4180), `\n` line
  ends. Columns, in this order: `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`. These seven columns
  and their order are stable. New columns, if ever added, are appended at the end in a minor release.
- **JSON** (`exporter::writeJson`): a top-level array of objects with the keys `number`, `time`, `time_epoch`, `source`,
  `destination`, `protocol`, `length`, `info`. These keys, their JSON types and their meaning are stable; keys may be added
  in a minor release, so readers must ignore unknown keys. Row order follows the displayed (sorted) packet list.
- The text of `Info`, `Protocol`, `Source` and `Destination` is what the packet list shows. See "Not stable" for what that
  implies.

What enforces it: `tests/test_export.cpp` (`ExportTables.*`, `ExportCapture.*`), which pin the CSV header and a row, the JSON
key order and escaping, and pcap/pcapng round trips.

### 5. Supported platforms and toolchains

Supported means built and tested in CI on every change (`.github/workflows/ci.yml`) and, for packaging, built by
`.github/workflows/release.yml`:

| Platform | Architecture | Notes |
|---|---|---|
| Linux (Ubuntu 24.04 baseline) | x86_64 | `.tar.gz`, `.deb`, AppImage; GCC or Clang with C++20 |
| macOS 15 | arm64 | `.dmg`, ad hoc signed (not notarized) |
| Windows (CI: windows-2025) | x86_64 | `.zip`; MSVC (Visual Studio 2022) |

Other platforms and compilers may work (source builds on other Linux distributions are expected to), but are not covered
by this promise. Dropping an operating system release from the supported list is announced in a minor release and takes
effect no earlier than the next minor release. The build requirements are CMake 3.21 or later, a C++20 compiler and the
dependencies pinned by `vcpkg.json` (see [BUILDING.md](BUILDING.md)). Live capture needs libpcap (Npcap on Windows) and
privileges; see [CAPTURE_PRIVILEGES.md](CAPTURE_PRIVILEGES.md).

## Not stable

These can change in any release, including patch releases:

- **UI layout and behaviour of windows**: menus, panels, colours, themes, default window size, keyboard shortcuts (shortcut
  changes are noted in release notes where practical), dialogs, status bar text.
- **Internal C++ APIs.** `core/` is an implementation library of the application, not a public SDK: headers, namespaces,
  class layouts and the `imshark_core` target may change at any time.
- **Dissector tree text** (the Details pane), the **Info column text**, protocol column names, and hex-dump
  presentation. They are written for people. Parse fields through the display filter or `imshark_dump`, not by scraping
  these strings (the CSV and JSON `Info` columns share this caveat).
- **Which protocols are decoded, and how deeply.** Coverage grows; a packet that was shown as raw data may be decoded in
  a later release, and the filter fields it yields change accordingly (additions only).
- **Statistics window contents, coloring rule defaults, packet comments display, and the Follow Stream text view.**
- **Build options and CMake targets** other than the output binaries named above.
- **Performance, memory use and resource limits.** The bounded-memory budgets are a safety property (see
  [THREAT_MODEL.md](THREAT_MODEL.md)); their exact values are not a compatibility surface.
- **Pre-1.0 behaviour.** Nothing in 0.x is covered, except that settings files from 0.x load as version 0.
- **Files in `tools/`** other than `imshark_dump` as described above.

## Reporting a break

If a 1.x release breaks something listed under "Stable", that is a bug: open an issue. A break found after a release is
fixed in a patch release, or the release is documented as the incompatible one and a 2.0 is planned.

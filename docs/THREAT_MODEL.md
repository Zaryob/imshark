# Threat Model

ImShark is a desktop packet analyzer. Its job is to parse data it does not control: capture files from other people,
traffic from a live network, and key material. This document says what is being protected, where the trust boundaries
are, who the attackers are, what the code already does about it (with the file or test that shows it), what risk is left,
and what is out of scope. Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).

Line numbers refer to the tree at the time of writing. Treat the file and symbol names as the stable part.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The user's account and files | A parser bug that gives code execution runs as the user (or, for live capture, possibly with elevated rights; see section 3.8). |
| Availability of the application | Opening a file must not hang the machine, exhaust RAM or fill the disk. |
| Confidentiality of captured data and TLS secrets | Captures hold private traffic; key logs and pcapng Decryption Secrets Blocks (DSB) decrypt it. |
| Integrity of the user's source capture and settings | Exports and saves must not overwrite or corrupt what the user already has. |
| Integrity of the release artifacts | Users run the downloaded binaries. |

## 2. Trust boundaries and attackers

| Boundary | Crosses it | Attacker |
|---|---|---|
| Capture file on disk -> parsers | file bytes, gzip wrapper, pcapng options and DSBs | Anyone who can make the user open a file (email, download, shared capture). The primary attacker. |
| Network -> live capture -> parsers | frames from the wire | Any host on the sniffed network, including hosts that only send packets. |
| Key log file -> TLS decryptor | text lines | A file the user selects; may come from someone else. |
| Settings file -> application | text lines | A local process of the same user, an older/newer ImShark, a damaged disk. Not a privilege boundary. |
| Filter / color rule strings -> filter compiler | expressions typed by the user or stored in settings | Content pasted from a tutorial, a shared settings file. |
| Drag-and-drop / command line paths -> loader | path strings | The desktop environment; a user tricked into dropping a file. |
| Temporary directory | decompressed copy of a `.gz` capture | Other local users on a shared system. |
| GUI process -> privileged capture helper (live capture) | interface name, capture options, packets | A compromised or malicious GUI side input. See section 3.8. |
| Source repository / dependencies / CI -> released binaries | source, vcpkg ports, workflow actions | Supply-chain attackers. |

Out-of-boundary attackers are listed in section 5.

STRIDE letters used below: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
service, **E**levation of privilege.

## 3. Threats, mitigations and residual risk

### 3.1 Malicious capture files (all readers)

Readers: pcap, pcapng, snoop, iptrace, ERF, NetMon (`core/src/io/*_reader.cpp`), then the dissectors.

Threats: memory corruption from length fields that lie (E, D); huge declared sizes that make the loader allocate
(D); truncated or inconsistent records (D, T); deeply nested or looping protocol structures (D); packets crafted to
make one connection or one reassembly consume unbounded memory (D).

Mitigations and evidence:

- **Record sizes are checked against the file.** Every reader refuses a record larger than `kMaxRecordSize` (256 MiB,
  `core/src/io/reader_util.h:17`) or larger than the bytes that remain: `pcap_reader.cpp:71`, `snoop_reader.cpp:88`,
  `iptrace_reader.cpp:67`, `netmon_reader.cpp:125`, `pcapng_reader.cpp:143` (block length must also be a multiple of 4 and at least 12).
- **Allocation is not driven by the header.** `reservePackets` caps the up-front reservation at 32 Mi elements and treats
  failure as harmless (`core/src/core.cpp:15-25`). The size of the per-packet record is pinned by a compile-time budget,
  `kPacketInfoSizeBudget` (`core/src/packet/packet_info.h:174`).
- **Truncated files load what is complete.** `tests/test_truncated_load.cpp` (`TruncatedLoad.*`) cuts every format in its
  last record and requires the same result as a clean cut; `PcapngWithoutAnyCompletePacketStillFails` pins the error case.
- **Truncation and mutation sweeps over frames.** `framesweep::sweep` (`tests/frame_sweep.h`) parses each hand-built frame
  cut at every length plus seeded random mutations, and checks that every tree node stays inside the frame
  (`expectInside`). It is used by the per-protocol test files (more than 50 test files contain a truncation, mutation or
  sweep case; examples: `DatagramReassembly.FuzzGarbageNeverCrashesOrBreaksTheBudget`,
  `Gzip.RandomCorruptionNeverCrashesOrHangs`, `CaptureInfo.DamagedOptionsAndRecordsNeverCrash`).
- **Bounded protocol state.** Stream reassembly: `kMaxBuffer` 8 MiB per direction, `kMaxPending` 1 MiB, `kMaxDirections`
  100000 (`core/src/dissect/tcp_streams.h:55-57`, test `TcpReassembly.IncompleteDirectionsAreBoundedInMemory`). IP and
  datagram reassembly: 1024 pending items and 64 MiB total (`core/src/network/ip_reassembly.h:55-56`,
  `datagram_reassembly.h:58-60`, test `DatagramReassembly.ByteBudgetEvictsTheOldestAndStaysBounded`). Session tables:
  64 MiB per table (`core/src/dissect/session.h:56`). Application-layer caps: HTTP headers 64 KiB and decoded bodies 16 MiB
  (`http.cpp:71-73`), TLS handshake 1 MiB (`tls.cpp:38`), and per-protocol caps for ONC RPC, DCE/RPC, SMB2, NFS, LDAP, MySQL,
  PostgreSQL, Kerberos (`kMax*` constants in their headers; the DCE/RPC and RPC cases have tests such as
  `DceRpcFlows.TheBudgetRunningOutIsSaidInTheTree`).
- **Sanitizers in CI.** `IMSHARK_SANITIZE` builds core and UI with AddressSanitizer and UndefinedBehaviorSanitizer and
  `-fno-sanitize-recover=undefined` (`CMakeLists.txt:44,56-61`), with a guard that fails the configure if the core is not
  instrumented (`CMakeLists.txt:66-70`). CI runs the whole test suite with it on Linux and macOS
  (`.github/workflows/ci.yml:26-34`). MSVC builds are not sanitized.
- **Fuzzing** is being added: see [FUZZING.md](FUZZING.md) for the harnesses and corpus once it lands. Until then the
  sweeps above are the evidence; they are deterministic and do not explore like a coverage-guided fuzzer.
- **Loader checks.** The loader refuses anything that is not a regular file (`src/ui/loader.cpp:67`), so a FIFO or
  device path cannot block it.

Residual risk: the dissectors are a large body of C++ written against a hostile-input rule but never audited as a whole.
A memory-safety bug in a dissector is the most likely serious vulnerability. The sweeps and sanitizers reduce but do not
exclude it. Resource limits are per table, so a capture that uses many tables at once can still use several times a single
budget; the user can cancel a load.

### 3.2 gzip-wrapped captures

Threats: decompression bomb (D: RAM or disk), malformed deflate streams (E, D), a CRC/size mismatch used to feed
inconsistent data (T).

Mitigations:

- The inflater is in-tree (`core/src/gzip.cpp`) and rejects bad block types, bad headers and reserved flags, and checks
  CRC32 and ISIZE of every member (`gzip.cpp:291-292`). Tests: `Gzip.DamagedFilesAreReported`,
  `Gzip.RandomCorruptionNeverCrashesOrHangs`.
- In-memory decompression (used for HTTP bodies) has a hard output cap (`gunzipMemory`, `gzip.cpp:302`; HTTP: 16 MiB).
  Test `GzipMemory.RejectsDamagedTruncatedAndOversizedData`.
- File decompression is cancellable and reports progress (`LoadControl`); test `Gzip.CancellationStopsTheDecompression`.

Residual risk: **`gunzipFile` writes to a temporary file without an output size limit** (`gzip.cpp:346`:
`Output output(outFile)` uses the default `UINT64_MAX`). A small `.gz` can expand to a file that fills the temporary
directory before the user cancels. The packets then keep file offsets into that copy, which is why it exists
(`src/ui/loader.cpp:75-80`). This is a known gap and is tracked as a hardening item (a configurable cap and a free-space
check).

### 3.3 pcapng options, DSBs and comments

Threats: option lists that run past the block (E, D); duplicated or huge option values (D); a DSB that carries
attacker-chosen "secrets" to cause expensive or misleading decryption (D, S); comments and names that inject terminal or
UI-affecting text (T).

Mitigations: option parsing is bounded by the enclosing block length (`pcapng_reader.cpp:143`; test
`CaptureInfo.DamagedOptionsAndRecordsNeverCrash`, `CaptureInfo.PcapngMetadataInBothByteOrders`). DSB bytes kept in memory
are capped at 32 MiB (`pcapng_reader.cpp:23`). The DSB parser feeds the same key-log parser as a key log file (3.4), with the
same caps. Strings from files are displayed through Dear ImGui text widgets as data; the application never executes them.

Residual risk: a crafted DSB can make the decryptor try secrets that do not match; the result is a failed decryption, not
a wrong plaintext, because record authentication tags are checked (state `TagFailure`, `core/src/dissect/tls_decrypt.cpp:159`). Comment text is shown as given, so it can be misleading
(spoofing of what the capture "says").

### 3.4 TLS key log files and embedded secrets

Threats: oversized or malformed log (D); log that the user did not intend to trust (S); secrets leaking through exports (I).

Mitigations: the file size is limited to 256 MiB, a line to 4096 bytes, and the store to 200000 client randoms
(`core/src/tls/keylog.h:96-98`, `keylog.cpp:134,158,174`); malformed lines are counted and do not stop the parse
(`TlsKeyLog.MalformedLinesAreCountedAndDoNotStopTheParse`, `TlsKeyLog.StoreIsBounded`). Secrets are held in memory only. Pcapng export writes the capture's secrets as DSBs on purpose so that a
decrypted capture stays decryptable, and the user guide says so (`docs/USER_GUIDE.md`, Export and Capture file properties:
"note about embedded TLS secrets"). Decryption is optional at build time (`IMSHARK_TLS_DECRYPT`).

Residual risk: **exporting a pcapng from a decrypted session shares its secrets** with whoever receives the file. This is
by design and documented; there is no per-export "strip secrets" switch yet. Key logs are read whole into memory.

### 3.5 Settings file

Threats: tampering by another local process (T), a damaged file or a file from a different version (D, T of the user's
preferences), a crash during a write leaving a half-written file (D), values that trigger a parser bug (E).

Mitigations:

- Every value is validated and falls back to its default; numbers must be complete and in range
  (`src/ui/settings.cpp`, tests `Settings.MissingOrDamagedFilesGiveDefaults`, `Settings.NumericValuesMustBeComplete`,
  `Settings.InvalidWindowGeometryIsIgnored`).
- Values that come from history lists cannot inject other keys: line breaks are flattened on write
  (`Settings.HistoryCannotInjectOtherSettings`).
- The file is versioned (`settings_version`). A file from a newer version is never overwritten, a corrupt file is copied to
  `settings.ini.bak-<timestamp>` before it is replaced, and saves are atomic (temp file in the same directory, then rename)
  so a crash or a failed write keeps the old file (`settings.cpp:47` `inspectFile`, `:86` `backUpFile`, `:232`
  `saveSettings`, `:256` rename; tests `SettingsVersion.*`). Files over 1 MiB are not read as settings
  (`settings.cpp:33`).
- The settings can name a TLS key log path and a capture interface and filter. They are inputs to code that validates
  them (3.4; the capture filter is compiled by libpcap and, with the privileged helper, validated again on the other side
  of the boundary, see 3.8).

Residual risk: any process running as the user can edit the file; that is not a privilege boundary (section 5). The
temporary file name is not secret, and the file has the user's default permissions (not restricted to the owner on
systems with a permissive umask); it holds no secrets other than file paths and filter history.

### 3.6 Coloring rules and display filter strings

Threats: an expression that makes the compiler or evaluator consume unbounded CPU or stack (D); an invalid regular
expression (D); a filter that is wrongly accepted and hides packets (T in the sense of misleading display).

Mitigations: the filter is compiled once into a tree, errors are reported with a position and never abort the program
(`core/src/filter/filter.cpp`; `std::regex_error` is caught at `filter.cpp:355-358`). Coloring rule lines are parsed strictly
(six fields, hexadecimal colors of exactly six digits, expression without tabs: `src/ui/color_rules.cpp:99-114`; tests in
`tests/test_color_rules.cpp`) and invalid rules are skipped. Filters read the packet summary, never the raw buffer.
Filter history is capped at 15 entries and settings cannot grow without bound (`Settings::kMaxFilterHistory`).

Residual risk: `matches` uses `std::regex` (ECMAScript), which can be slow on some patterns and deep on recursion for long
inputs. A pathological pattern can make a filter run very slowly or exhaust the stack. The pattern is typed by the user or pasted by the user into a settings file, so
the attacker needs the user's help. How regular expressions are threaded and bounded is being reworked separately;
the answer will be reflected here.

### 3.7 Drag-and-drop, command-line paths, exports, temporary files

Threats: opening a path that is not a capture (D); symlink or hard-link tricks so that an export overwrites the source
capture (T); predictable temporary file names (T, I); stale temporary files (I).

Mitigations:

- Dropping a file or passing it on the command line goes through the same loader; only the first dropped path is used
  (`src/ui/live_capture.cpp:413-415`) and the loader requires a regular file (`loader.cpp:67`). The loader never executes
  anything from a file.
- Export refuses to overwrite the capture it reads from, including through a hard link or alias
  (`core/src/export/export.cpp:117`, `std::filesystem::equivalent`; tests `ExportCapture.CannotOverwriteTheSourceCaptureInAnyFormat`,
  `ExportCapture.CannotOverwriteTheSourceThroughAHardLink`). A cancelled or failed export leaves no partial file
  (`ExportCapture.FailuresAndCancellation`).
- The decompressed copy of a `.gz` goes in the user's temporary directory and is removed when the capture is closed, replaced
  or the application exits (`src/ui/loader.cpp:46-51,159-164,222-225,246-250`). Non-gzip captures are read in place and
  never copied.

Residual risk: the temporary name is `imshark_<steady clock ticks>_<counter>.cap` (`loader.cpp:60`) and is opened with a plain
`ofstream` (follows symlinks, no exclusive create). On systems with a shared, world-writable temporary directory
(typical Linux `/tmp`), a local attacker could guess the name and plant a symlink. macOS and Windows use a per-user
temporary directory, which removes the exposure there. A crash leaves the temporary file behind. Hardening (exclusive
create, a private subdirectory with mode 0700, startup cleanup) is a candidate item.

### 3.8 Live capture and the privilege boundary

Threats: a parser bug triggered by wire traffic running with elevated rights (E); a malicious interface name or BPF
filter reaching privileged code (E, T); captured packets written where the user cannot write or over a file the attacker
chose (T); a remote host sending traffic crafted to crash the viewer (D).

Design (see [CAPTURE_PRIVILEGES.md](CAPTURE_PRIVILEGES.md) for the authoritative description): the GUI and the dissectors
never run with elevated privileges. A separate helper may open the interface with administrator rights and drops those
rights before it touches any user file. Packets cross from the helper to the unprivileged GUI, which parses them like any
other untrusted data. Inputs sent to the helper (interface name, snap length, promiscuous flag, filter text) are treated as
untrusted by the helper.

Mitigations: offline analysis needs no privileges at all (`docs/BUILDING.md`: "Offline analysis needs no capture
privileges"); a build without libpcap disables the Capture menu (`IMSHARK_LIVE_CAPTURE`, preset `minimal`). Settings that feed
capture options are range-checked on load (snap length 64 to 262144: `settings.h`, `Settings.CaptureOptionsRoundTripAndDefaults`).
Live frames use exactly the same parsing paths as files, so 3.1 applies to them.

Residual risk: a vulnerability in the helper, or in libpcap/Npcap, is out of ImShark's control and could give the attacker the
helper's rights. Until the helper is the only way to capture, granting capabilities directly to the GUI binary (as the build
guide describes for `CAP_NET_RAW`) means a dissector bug would run with them. Prefer the helper once available. A remote
attacker can always cause *some* traffic to be captured and displayed; they cannot choose where it is saved.

### 3.9 Packaging and supply chain

Threats: a compromised dependency or port (T, E); a mutable action or tool that changes what is built (T); a tampered
release artifact (T); users unable to tell an official build from a copy (S).

Mitigations:

- **Dependencies are pinned.** `vcpkg.json` has a `builtin-baseline` commit (line 8); `.github/actions/setup-vcpkg` reads it and
  checks out exactly that vcpkg commit (`action.yml`, "Read the pinned registry baseline"). Local overlay ports are in
  `vcpkg-ports/` and are covered by the cache key. Binary caches are keyed on the manifest and overlay hashes.
- **CI has minimal rights.** Workflows declare `permissions: contents: read` (`ci.yml:10`, `release.yml:7`); only the publish
  job gets `contents: write` (`release.yml:163-164`). Release publication needs a tag, the tag must match the versions in
  `CMakeLists.txt` and `vcpkg.json` (`release.yml:36-38`), and the full CI matrix runs first (`release.yml:49`).
- **Third-party tools are checksummed.** The AppImage tools are downloaded from fixed release URLs and verified with
  `sha256sum --check` before use (`release.yml:122-124`).
- **Release set is checked and checksummed.** The publish job requires exactly the five expected packages, rejects empty
  files, and writes `SHA256SUMS.txt` (`release.yml:173-203`).
- **macOS bundle** is signed ad hoc after `fixup_bundle` rewrote the libraries (`CMakeLists.txt:190-194`), which is what
  Apple Silicon requires to launch it. It is not Developer ID signed or notarized (`docs/BUILDING.md`).
- **Offline verification:** the Docker job builds from the manifest and starts the application with `--network none`
  (`ci.yml`, "Linux / Docker").
- Dependency license notices ship with packages (`docs/BUILDING.md`).

Residual risk:

- GitHub Actions are referenced by major-version tags (`actions/checkout@v7`, `softprops/action-gh-release@v3`,
  `ilammy/msvc-dev-cmd@v1`, and others), not by commit SHA. A moved tag changes what runs, with the publish job's write token.
  Pinning by SHA is a hardening item.
- `SHA256SUMS.txt` is published next to the packages by the same workflow, so it detects corruption and mismatched
  mirrors but not a compromise of the release itself; there are no detached signatures or build provenance attestations yet.
- Windows and Linux packages are not code-signed. macOS is ad hoc signed only, so Gatekeeper requires the user to approve
  it, and the signature carries no identity.
- vcpkg builds from source (or from the keyed binary cache) on runners whose images change; builds are not bit-for-bit
  reproducible.
- The vcpkg registry baseline is trusted: a malicious port at that commit is not detected beyond vcpkg's own source hash checks.

## 4. Summary of the main residual risks

| # | Risk | Where | Status |
|---|---|---|---|
| 1 | Memory-safety bug in a dissector | 3.1 | Reduced by sweeps, sanitizers; fuzzing coming (FUZZING.md) |
| 2 | Unbounded size of the decompressed `.gz` temporary file | 3.2 | Open; hardening item |
| 3 | Predictable temp file name in shared `/tmp` | 3.7 | Open; hardening item |
| 4 | Regular-expression filters can be slow | 3.6 | Being reworked separately |
| 5 | pcapng export carries TLS secrets | 3.4 | By design, documented |
| 6 | Actions pinned by tag, not SHA; no signatures/provenance | 3.9 | Open; hardening item |
| 7 | GUI binary with direct capture capabilities | 3.8 | Reduced once the helper is used |

## 5. Out of scope

- An attacker who already runs code as the user (they can edit settings, replace the binary, read memory).
- Physical access to the machine, a compromised operating system, kernel or GPU driver bugs.
- Vulnerabilities in third-party code that ImShark links (Dear ImGui, GLFW, OpenSSL, libpcap/Npcap, the C++ standard library)
  beyond choosing and pinning their versions; report those upstream, and tell us if ImShark's use makes them worse.
- Confidentiality of the packets while the user is looking at them: the screen, the clipboard (copy actions are the user's
  choice) and exported files are the user's responsibility.
- Cryptographic weaknesses in the captured protocols themselves; ImShark decrypts only with secrets it is given.
- Anything about the correctness of dissection as evidence (forensic or legal use); see [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
- Denial of service by a legitimately huge capture that the machine simply cannot hold; the load can be cancelled.
- Network attacks on the update path: ImShark has no auto-update or telemetry and makes no network connections itself
  except through the capture interface the user chooses.

## 6. Keeping this document true

Change this file in the same pull request as any change to a trust boundary: a new file format reader, a new place that
writes files, a new external process, a new network use, a workflow change, or a change of the budgets named above. The
unit tests cited here are the evidence; if one is renamed, update the reference.

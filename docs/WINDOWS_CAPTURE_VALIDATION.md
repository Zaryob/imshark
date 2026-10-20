# Windows capture validation — 20 October 2026

This record separates native Windows IPC evidence from real Npcap capture and interactive UAC checks. The latter
remain open. The published 1.0.0 ZIP is still an offline-analysis build.

## Source and environment

- Original Windows implementation: `3c42d756c0448c4b4418087a043efb390a1b98bc` (local source after the 1.0.0 release).
- Tested capture code: `18c2d0a2793e045cb2b88adc19b23f862f9873c2` on `codex/windows-capture-validation`.
- [Windows Actions run](https://github.com/Zaryob/imshark/actions/runs/39474798160), workflow `.github/workflows/windows-capture.yml`.
- GitHub `windows-2025`, x86_64, MSVC 19.51.36260.0, Windows SDK 10.0.26100.0.
- Npcap SDK 1.16, downloaded from the vendor with SHA-256 verification (hash pinned in the workflow).
- No driver is installed by this workflow. The native scenarios use synthetic packet sources and real Windows pipes
  and child processes; they do not open a network interface or a real authorization prompt.

## Automated results

| Check | Result |
|---|---|
| Standalone native IPC executable, using the production capture/worker/stream code | Passed |
| Npcap-enabled capture backend, compiled and linked against the SDK import library | Passed; executable not run with a driver |
| Twelve native IPC scenarios, repeated ten times | 120 scenario runs, zero failures |
| Default offline Windows application and capture/documentation regressions | Pending final job result |
| macOS Release build and capture/documentation regressions after the changes | 81 selected tests: 78 passed, 3 skipped, zero failures (3.97 seconds) |

The twelve scenarios cover: exact pcap bytes, one-byte input chunks, malformed/truncated streams retaining earlier
packets, cancellation before connection, stopping an idle connected reader, connection timeout, prompt handling of a
failed authorization producer, a client connecting before the server waits, repeated session restarts, the real worker
stream writer's snap length and timestamps, an idle worker noticing GUI disconnection, and child-process arguments
including empty values and an executable path with spaces and `İ`.

The failed authorization scenario injects a failed process starter; it does **not** test rejection of a real UAC dialog.
The saved-pcap comparison checks the capture writer, not the GUI export/reopen flow.

The native log ends with:

```text
Native IPC scenarios: 12, failed: 0
```

CTest executes the native executable ten times with `--repeat until-fail:10`. Logs are uploaded as the
`windows-capture-validation` artifact on the linked run. `windows-offline-regressions` holds the separate default-build logs.

The macOS skips are the optional UI-cost benchmark (no fixture supplied), the disabled-backend test (not applicable to
this live-capture build), and the permission-dependent live loopback test. They are not successful driver checks.

## Corrections made during verification

- Keep the UTF-16 executable path alive until `ShellExecuteExW` returns, and remove an invalid `SpawnResult` member access.
- Quote empty Windows command-line arguments, including an empty BPF filter, so worker arguments retain their positions.
- Read an overlapped Named Pipe with an `OVERLAPPED` operation and wait for cancelled connection/read operations to
  finish before releasing their event and stack state. See Microsoft's [ReadFile contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
- Notice a failed producer before waiting out the connection timeout and preserve its failure message.
- Check idle-worker disconnection with a zero-byte write on the write-only handle; `PeekNamedPipe` needs read access.
- Drain buffered worker output before a clean source EOF; immediate client closure can otherwise lose unread packets.
- Remove the unsupported `npcap-users` group command from the documentation and setup guidance; use Npcap's documented admin-only behavior.
- Make zero uid/gid parser expectations platform-specific; Windows does not use POSIX uid/gid privilege dropping.
- Separate the packet-consumer adapter from the recorder so native IPC tests can link the production recorder without
  pulling in the dissector/UI stack. The normal application still uses the same consumer function.

## Reproduce native IPC checks

From an x64 Visual Studio developer PowerShell:

```powershell
cmake -S tools/windows_capture_validation -B build-windows-capture -G Ninja -DCMAKE_BUILD_TYPE=Release "-DNPCAP_SDK_DIR=C:/Npcap SDK"
cmake --build build-windows-capture
ctest --test-dir build-windows-capture --output-on-failure --repeat until-fail:10
```

The standalone project uses no vcpkg dependencies. With `NPCAP_SDK_DIR`, it also builds `npcap_link_check` to verify the
Npcap-enabled backend's compilation and linkage; CTest runs the offline IPC executable. In the normal project,
`windows_capture_native_ipc` is included in CTest on Windows.

## Still required for live-capture sign-off

Use the [Windows live capture checklist](RELEASING.md#10-windows-live-capture-checklist) on a Windows 10/11 machine or VM
with a real Npcap installation: DLL discovery, actual interface enumeration and packet capture, direct/admin-only
access, UAC accept/reject/cancel, GUI responsiveness, worker cleanup, BPF/snaplen, and exported pcap/pcapng reopening.
The [clean-machine ZIP checklist](RELEASING.md#9-windows-clean-machine-checklist) is also still open. Neither an SDK
link check nor the native IPC result above is evidence that those driver, desktop and package scenarios passed.

# Fuzzing

ImShark parses capture files and packets from untrusted sources, so the parsers are fuzzed with coverage-guided
[libFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses under AddressSanitizer and UndefinedBehaviorSanitizer. The
unit tests contain truncation and mutation sweeps; the harnesses add coverage feedback, long runs and a corpus that
grows with every run. A clean run is evidence for the inputs it explored, not a proof of absence of bugs.

## Harnesses

All harnesses live in `fuzz/`, export `LLVMFuzzerTestOneInput`, are deterministic, use no network, bound their memory by
capping the input size, and create temporary files only with per-process unique names (removed on return).

| Harness | Input | What it drives |
|---|---|---|
| `fuzz_capture_file` | a capture file | gzip unpacking, format detection, the pcap, pcapng, NetMon, snoop, ERF and iptrace readers, `FileProcessor::processFile` (summaries, reassembly, session tables), statistics, display filters over the summaries, and `buildPacketDetails` (Replay) for the first 64 packets |
| `fuzz_packet` | byte 0 link type selector, byte 1 options (ESP-NULL heuristic, FCS, truncation), then one frame | Full, Summary and Replay dissection of the frame, the field-offset invariant, and every extractor of the display filter field table |
| `fuzz_packet_sequence` | selector bytes, then `uint16 length, frame` records | frames fed through `FileProcessor::appendLivePacket` like a capture (TCP / IP / DTLS reassembly, TLS, DTLS, SCTP, DCE/RPC, ONC RPC, SMB2, database, FTP-DATA and TFTP session tables), then `buildPacketDetails` of every packet from a temporary pcap |
| `fuzz_filter` | a display filter expression | `filter::Filter::compile` and evaluation against HTTP, DNS and ARP sample packets, with and without capture context |
| `fuzz_gzip` | a gzip file | `gunzipMemory` and the streaming `gunzipFile` path, which must agree |

Besides sanitizer reports, a harness aborts when an invariant of the library breaks (`FUZZ_CHECK` in
`fuzz/fuzz_common.h`): every field of the tree lies inside the frame, a failed compile or decompression carries an error
message, and both gzip paths produce the same bytes.

## Building and running

The fuzz preset needs Clang with the libFuzzer runtime. On Ubuntu: `sudo apt-get install clang-18 libclang-rt-18-dev`.

```sh
export VCPKG_ROOT=...                     # as for any build, see BUILDING.md
cmake --preset fuzz -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18
cmake --build --preset fuzz
```

The preset builds Debug with `-O1 -fsanitize=fuzzer-no-link,address,undefined` (a sanitizer finding aborts instead of
printing and continuing), switches live capture, the tools and the unit tests off, and fails at configure time if the
compiler cannot link libFuzzer (`IMSHARK_FUZZ_ENGINE=LIBFUZZER`). The harnesses are in `build-fuzz/fuzz/`.

**macOS.** Apple Clang ships no libFuzzer. Install LLVM from Homebrew (`brew install llvm`) and use the `fuzz-macos`
preset, which points at `/opt/homebrew/opt/llvm` (adjust the paths in `CMakePresets.json` for an Intel Mac, `/usr/local/opt/llvm`).
That preset has not been tried on every macOS version; if linking libFuzzer fails, run the harnesses on Linux or in a container.

**Run one harness.** Work on a copy of the seed corpus, so the repository stays unchanged:

```sh
mkdir -p work/corpus work/crashes
cp -r fuzz/corpus/fuzz_packet work/corpus/
build-fuzz/fuzz/fuzz_packet -max_total_time=300 -rss_limit_mb=2048 -timeout=10 -max_len=4096 \
    -dict=fuzz/dict/packet.dict -artifact_prefix=work/crashes/fuzz_packet- work/corpus/fuzz_packet
```

`fuzz/run_fuzzers.sh [-b build-dir] [-t seconds] [-w workdir] [-m] [harness...]` does the above for all (or the named)
harnesses with the settings CI uses (`-max_len` and the dictionary per harness) and keeps going if one fails. `-m` minimizes
the evolved corpus afterwards. Add `-jobs=4 -workers=4` to use several cores.

**Reproduce a crash.** Every failure leaves a `crash-*`, `leak-*`, `timeout-*` or `oom-*` file in the artifact prefix
directory (CI uploads them as the `fuzz-crashes` artifact):

```sh
build-fuzz/fuzz/fuzz_packet work/crashes/fuzz_packet-crash-1234abcd      # run it once
build-fuzz/fuzz/fuzz_packet -minimize_crash=1 -runs=10000 work/crashes/fuzz_packet-crash-1234abcd   # shrink it
```

Fix the bug, add a regression test to the matching `tests/test_*.cpp` that builds the same input, and add the (minimized)
reproducer to `fuzz/corpus/<harness>/` so the replay test keeps it fixed.

## Without libFuzzer

In every normal build (any compiler, including MSVC) the harnesses are built as ordinary executables linked with
`fuzz/standalone_main.cpp`, and CTest runs one test per harness, `fuzz_replay_<harness>`, that replays the seed corpus:

```sh
ctest --preset debug -R fuzz_replay
```

The same executables accept files and directories on the command line, which reproduces a crash input without libFuzzer. With a
sanitizer build (`-DIMSHARK_SANITIZE=ON`) the replay runs under ASan and UBSan.

The standalone driver also has a small, coverage-blind mutation mode for machines that have no libFuzzer (it accepts the
libFuzzer option names `-max_total_time`, `-max_len`, `-dict`, `-artifact_prefix`, plus `-mutate=N` and `-seed=S`, and ignores the
others). It is much weaker than libFuzzer, but finds shallow bugs and is reproducible:

```sh
cmake --preset debug -B build-san -DIMSHARK_SANITIZE=ON
cmake --build build-san --target imshark_fuzzers
fuzz/run_fuzzers.sh -b build-san -t 120 -w work
```

The input being run is written to `<artifact_prefix>last-input` first; if the process dies, that file is the reproducer.

## Corpus policy

- `fuzz/corpus/<harness>/` holds small seeds that are checked in and replayed by CTest. The directory must stay small (the
  whole tree is under 100 KB; keep it under 2 MB) and contain only files that may be redistributed.
- Seeds are derived by `python3 tools/make_fuzz_seeds.py` from the synthetic fixtures already in the repository
  (`tests/corpus`, `tests/data`, made by `tools/make_corpus.py`, `tools/make_sample_pcap.py`, `tools/make_tls_fixtures.py`) and
  the filter expressions in `tests/test_filter.cpp`; it also regenerates `fuzz/dict/filter.dict` from `docs/FILTER_FIELDS.md`.
  Re-run it when fixtures or filter fields change. Never add real captures: they may carry private traffic.
- Evolved corpora (what a long run finds) are not committed. CI keeps them in the Actions cache, so every run starts where
  the previous one stopped. Minimize a corpus with `-merge=1` before sharing one.
- A reproducer of a fixed bug is the one kind of file added to the corpus by hand: minimize it, name it after the bug
  (`regress-<what>`), and add the regression test next to it.
- Dictionaries (`fuzz/dict/`): `capture_file.dict` (magic numbers, pcapng block types and options), `packet.dict` (TLS, HTTP/1,
  HTTP/2 and HPACK, DNS, SMB2, DCE/RPC, SCTP and text protocol tokens) and `filter.dict` (operators and every field name).

## Continuous integration

- `ci.yml`, job `fuzz` (Ubuntu 24.04, clang-18): builds the preset, replays the corpus through CTest, then runs each harness
  for 60 seconds (`-rss_limit_mb=2048 -timeout=10`) on a corpus restored from the cache, on every push and pull request.
  Crash reproducers are uploaded as an artifact when it fails.
- `fuzz-nightly.yml`: every Sunday (or on demand, with the minutes per harness as input) each harness runs for 20 minutes on its
  own runner, and the minimized corpus is cached for the next run.

## Known limits

- Display filters with `matches` use `std::regex`, whose matching can be slow or deeply recursive on hostile patterns; the filter
  harness limits the expression to 2048 bytes and a pattern that runs into the 10 second timeout is reported as a finding.
- Decryption is only reached when the capture carries its own secrets (pcapng DSB); keys supplied by the user are not fuzzed.
- The live capture path and the UI are not fuzzed.

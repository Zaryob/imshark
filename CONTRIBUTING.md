# Contributing to ImShark

For a bug report, include the operating system, `imshark --version`, reproduction steps and a small capture if it can be shared safely. State what you expected and what ImShark displayed. Never include private traffic or session keys in a public issue.

## Development setup

Follow [docs/BUILDING.md](docs/BUILDING.md) for the compiler, vcpkg and platform prerequisites. All default-build C/C++ libraries come from the pinned vcpkg manifest; optional Windows live capture additionally requires the Npcap SDK and runtime. A normal development build is:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Run CTest serially and finish one preset's suite before starting another; some tests share temporary files across build directories. Parser and stateful protocol changes should also pass the GCC/Clang sanitizer configuration:

```sh
cmake --preset debug -DIMSHARK_SANITIZE=ON
cmake --build --preset debug
ctest --preset debug
```

Use `cmake --preset minimal`, its build preset and its test preset to check the APIs with TLS decryption and live capture disabled. An enabled test dependency is required: an absent GoogleTest must not silently turn a successful configure into an untested build.

## Code and delivery rules

Match the surrounding code and use the root `.clang-format` for changed C/C++ code when available. Keep unrelated reformatting out of a functional change. CMake source lists are explicit; register new files in `core/CMakeLists.txt` or `tests/CMakeLists.txt`.

A protocol delivery should satisfy these rules:

- Name the specification and supported version in [docs/PROTOCOLS.md](docs/PROTOCOLS.md); state unsupported or encrypted content honestly.
- Read only within the provided buffer and keep every field's byte range valid. Build the field tree only when `ctx.wantFields()` is true.
- Decide cross-packet state during the load pass; Replay reads the stored state and produces the same result. Bound state tables and report state loss.
- Preserve `PacketInfo`'s ABI-adjusted size budget (`kPacketInfoSizeBudget`). Reuse existing summary fields or session tables rather than growing every packet.
- Register filter fields in the protocol's `*_fields.cpp` module and update the explicit field-module lists. Filters must be gated on the relevant protocol.
- Add independently checked message vectors, truncation/mutation sweeps and Replay tests for stateful behavior. Real-capture hooks are optional when captures are unavailable; a skipped hook is not real-capture verification.
- Update the support matrix, specifications, user-facing limits and any changed user workflow. The README contains an overview; detailed protocol changes belong in the reference documents.

[docs/DISSECTORS.md](docs/DISSECTORS.md) provides the complete API guide and a test-compiled worked example. Keep that guide's marked example blocks synchronized with `tests/test_dissector_guide.cpp`.

## Generated documentation and snapshots

`docs/FILTER_FIELDS.md` is generated from the built-in field table and checked by the `Docs` tests. Regenerate after an intentional field change:

```sh
IMSHARK_UPDATE_DOCS=1 ctest --test-dir build-debug -R Docs --output-on-failure
```

The field snapshot also records types, descriptions and values on fixed packets. Run the affected test with `IMSHARK_UPDATE_SNAPSHOT=1` only for an intentional change, then inspect and commit the snapshot diff. Do not regenerate snapshots merely to hide a regression.

## Regression corpus

`tests/corpus/` contains small synthetic captures and `manifest.json` with source, SHA-256 and expected results. `python3 tools/make_corpus.py` regenerates the synthetic corpus and manifest deterministically; `--real-dir DIR` records optional real captures you already have.

Real captures stay outside the repository. Set `IMSHARK_CORPUS_DIR` to the directory holding the real files listed in the manifest; tests skip those checks otherwise and never download traffic. Check each capture's licence and privacy before adding a manifest entry. Expectations should come from the specification or an independent tool, rather than copying ImShark's output.

## Comparing with tshark

`imshark_dump` prints packet filter fields as JSON. `tools/compare_tshark.py` compares packet counts, protocol classifications and selected fields against tshark using the pinned version/preferences/aliases in `tools/compare_tshark.json`:

```sh
cmake --build --preset debug --target imshark_dump
python3 tools/compare_tshark.py --imshark-dump build-debug/imshark_dump tests/corpus
```

Add a real-capture directory as another positional argument when available. `--save-tshark-json DIR` retains raw tshark output; `--tshark-json-dir DIR` reuses a recording. The checked-in `tests/data/tshark` comparator fixtures are hand-written, so passing them validates the comparator rather than proving agreement with Wireshark.

Exit codes: `0` equal, `1` differences, `2` usage error, `3` missing dump tool, `4` tshark version mismatch, `77` tshark unavailable. CTest includes comparator fixtures and an optional corpus comparison. Decode As settings in the comparator configuration are passed only to tshark; the dump tool has no matching option.

## Coverage and performance

With Clang, `llvm-cov` and `llvm-profdata`, `tools/coverage.sh` prints a source coverage summary; `--html` also writes `build-cov/coverage-html/index.html`. Record the tested revision and excluded files when reporting coverage.

`python3 tools/benchmark.py --profile mixed --packets 500000` builds `bench_driver`, creates a temporary synthetic capture, measures load time, one filter pass and peak RSS, then deletes the capture. `--size-mb 1024` selects an approximately 1 GiB workload. Record the hardware, compiler, configuration, workload and cache conditions; synthetic traffic does not establish throughput for every dissector. Never commit large benchmark captures.

## Commits and releases

Use a short imperative subject describing the resulting change. Split independent changes into reviewable commits with relevant validation. Before submitting, run the normal tests and the sanitizer tests appropriate to the change and review documentation/snapshot diffs.

Local packaging, tag commands and release limitations are in [docs/BUILDING.md](docs/BUILDING.md#tagged-releases). Use annotated `vMAJOR.MINOR.PATCH` tags matching both the CMake project and vcpkg manifest versions, with notes in `docs/releases/<tag>.md`. Only a pushed version tag starts CI/CD; the release is published after all checks and platform packages succeed. Published tags are immutable; fixes require a new patch release.

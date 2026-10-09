## Summary

<!-- What changes and why? / Ne değişti ve neden? -->

## Checklist

- [ ] Normal tests pass (`ctest --preset debug`, run serially)
- [ ] Parser or stateful protocol changes pass the sanitizer configuration (`cmake --preset debug -DIMSHARK_SANITIZE=ON`)
- [ ] New or changed behavior has tests (message vectors, truncation/mutation sweeps, Replay tests where stateful)
- [ ] Snapshot diffs were regenerated with `IMSHARK_UPDATE_SNAPSHOT=1` only for an intentional change, and the diff was reviewed
- [ ] Generated docs (`docs/FILTER_FIELDS.md`) and hand-written docs are updated where needed
- [ ] New source files are registered in `core/CMakeLists.txt` or `tests/CMakeLists.txt`
- [ ] No unrelated reformatting; `.clang-format` applied to changed C/C++ code
- [ ] Sample captures added to the corpus have a compatible licence and no private data

## Related issues

<!-- Fixes #123 -->

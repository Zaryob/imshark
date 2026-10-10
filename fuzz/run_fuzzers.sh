#!/usr/bin/env bash
# Runs the libFuzzer harnesses for a bounded time each (CI, nightly and local use; see docs/FUZZING.md).
#
#   fuzz/run_fuzzers.sh [-b BUILD_DIR] [-t SECONDS] [-w WORK_DIR] [-m] [harness...]
#
#   -b  build directory of the fuzz preset                (default: build-fuzz)
#   -t  libFuzzer -max_total_time per harness, seconds    (default: 60)
#   -w  working directory for the evolving corpora and the crash files (default: fuzz-work)
#   -m  minimize each evolved corpus with -merge=1 after the run (keeps a cached corpus small)
#
# The seed corpus in fuzz/corpus is only read: each harness starts from a copy in WORK_DIR/corpus/<harness> (a restored CI
# cache of an earlier run is kept and extended). Crash, leak, timeout and OOM reproducers are written to
# WORK_DIR/crashes. All harnesses run even if one fails; the exit status is non-zero if any did.
set -u

build=build-fuzz
seconds=60
work=fuzz-work
minimize=0
while getopts "b:t:w:m" opt; do
    case "$opt" in
        b) build=$OPTARG ;;
        t) seconds=$OPTARG ;;
        w) work=$OPTARG ;;
        m) minimize=1 ;;
        *) sed -n '2,13p' "$0"; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

root=$(cd "$(dirname "$0")/.." && pwd)
all_harnesses="fuzz_capture_file fuzz_packet fuzz_packet_sequence fuzz_filter fuzz_gzip"
harnesses=${*:-$all_harnesses}

# input size limit (-max_len) and dictionary of each harness
max_len() {
    case "$1" in
        fuzz_capture_file) echo 65536 ;;
        fuzz_packet) echo 4096 ;;
        fuzz_packet_sequence) echo 16384 ;;
        fuzz_filter) echo 512 ;;
        fuzz_gzip) echo 8192 ;;
        *) echo 65536 ;;
    esac
}
dictionary() {
    case "$1" in
        fuzz_capture_file) echo "$root/fuzz/dict/capture_file.dict" ;;
        fuzz_packet | fuzz_packet_sequence) echo "$root/fuzz/dict/packet.dict" ;;
        fuzz_filter) echo "$root/fuzz/dict/filter.dict" ;;
        *) echo "" ;;
    esac
}

mkdir -p "$work/crashes"
status=0
for harness in $harnesses; do
    binary="$build/fuzz/$harness"
    if [ ! -x "$binary" ]; then
        echo "error: $binary not found (build the 'fuzz' preset first)" >&2
        status=1
        continue
    fi
    corpus="$work/corpus/$harness"
    mkdir -p "$corpus"
    cp -n "$root/fuzz/corpus/$harness"/* "$corpus"/ 2>/dev/null || true

    args=(-max_total_time="$seconds" -rss_limit_mb=2048 -timeout=10 -max_len="$(max_len "$harness")"
          -artifact_prefix="$work/crashes/$harness-" -print_final_stats=1)
    dict=$(dictionary "$harness")
    [ -n "$dict" ] && args+=(-dict="$dict")

    echo "::group::$harness (${seconds}s)"
    if ! "$binary" "${args[@]}" "$corpus"; then
        echo "error: $harness reported a failure; reproducers are in $work/crashes" >&2
        status=1
    fi
    echo "::endgroup::"

    if [ "$minimize" = 1 ] && [ -d "$corpus" ]; then
        merged="$work/merged/$harness"
        rm -rf "$merged"
        mkdir -p "$merged"
        if "$binary" -merge=1 -max_len="$(max_len "$harness")" -rss_limit_mb=2048 -timeout=10 "$merged" "$corpus" > /dev/null 2>&1; then
            rm -rf "$corpus"
            mv "$merged" "$corpus"
        fi
    fi
done
exit $status

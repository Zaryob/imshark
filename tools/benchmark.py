#!/usr/bin/env python3
"""ImShark performance benchmark: open a large pcap, measure load time and peak RSS.

Usage:
    python3 tools/benchmark.py [--build-dir build] [--pcap FILE] [--packets N]

If FILE does not exist, it is generated first (calls make_bench_pcap.py).
The imshark binary is run in headless/CLI mode via the core library test harness.
Since imshark is a GUI app, we use the 'imshark_tests' test binary with a custom
env flag IMSHARK_BENCH=1 that skips GUI and just loads the file, then reports timings.

If no test harness benchmark target exists, this script builds a small C++ bench
driver (tools/bench_driver.cpp) and compiles it against imshark_core.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.join(SCRIPT_DIR, "..")


def find_binary(build_dir: str, name: str) -> str | None:
    for sub in ["", "Release", "Debug"]:
        p = os.path.join(build_dir, sub, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def generate_pcap(path: str, n: int) -> None:
    script = os.path.join(SCRIPT_DIR, "make_bench_pcap.py")
    subprocess.run([sys.executable, script,
                    "--packets", str(n), "--output", path], check=True)


def run_bench(bench_bin: str, pcap: str) -> dict:
    """Run the bench binary and parse its output."""
    import resource
    t0 = time.monotonic()
    result = subprocess.run(
        [bench_bin, pcap],
        capture_output=True, text=True, timeout=120
    )
    elapsed = time.monotonic() - t0

    if result.returncode != 0:
        print("bench binary stderr:", result.stderr[:2000], file=sys.stderr)
        raise RuntimeError(f"bench binary exited with {result.returncode}")

    # Parse lines like:  packets=500000  load_ms=850  peak_rss_mb=185
    metrics: dict = {"wall_s": round(elapsed, 3)}
    for token in result.stdout.split():
        if "=" in token:
            k, v = token.split("=", 1)
            try:
                metrics[k] = int(v) if v.isdigit() else float(v)
            except ValueError:
                metrics[k] = v
    return metrics


BENCH_DRIVER_SRC = """\
// bench_driver.cpp — headless load benchmark for imshark_core
// Build: c++ -std=c++20 -O2 -I core/src bench_driver.cpp
//         -L build/core -limshark_core -o bench_driver
//   (or via CMake; see tools/benchmark.py)
#include <chrono>
#include <cstdio>
#include <string>
#include "core.h"          // core::FileProcessor

#ifdef __APPLE__
#  include <mach/mach.h>
static long peak_rss_kb() {
    struct mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS)
        return static_cast<long>(info.resident_size_max) / 1024;
    return -1;
}
#elif defined(__linux__)
#  include <sys/resource.h>
static long peak_rss_kb() {
    struct rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;   // already kB on Linux
}
#else
static long peak_rss_kb() { return -1; }
#endif

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "Usage: bench_driver <file.pcap>\\n"); return 1; }
    std::string path = argv[1];

    core::FileProcessor fp;
    core::LoadControl   ctrl;

    auto t0 = std::chrono::steady_clock::now();
    auto result = fp.load(path, ctrl, [](double){});
    auto t1 = std::chrono::steady_clock::now();

    long rss_kb = peak_rss_kb();
    long ms     = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!result.ok) {
        std::fprintf(stderr, "Load failed: %s\\n", result.error.c_str());
        return 1;
    }

    long n = static_cast<long>(fp.packets().size());
    std::printf("packets=%ld load_ms=%ld peak_rss_mb=%ld\\n",
                n, ms, rss_kb / 1024);
    return 0;
}
"""


def build_driver(build_dir: str) -> str:
    driver_src = os.path.join(REPO_ROOT, "tools", "bench_driver.cpp")
    driver_bin = os.path.join(build_dir, "bench_driver")

    if not os.path.exists(driver_src):
        with open(driver_src, "w") as f:
            f.write(BENCH_DRIVER_SRC)
        print(f"Wrote {driver_src}")

    # Try to build via cmake --build targeting bench_driver, or fall back to direct compile
    # First check if there's a CMake target for it
    core_lib = None
    for sub in ["core", "core/Release", "core/Debug"]:
        p = os.path.join(build_dir, sub, "libimshark_core.a")
        if os.path.exists(p):
            core_lib = p
            break

    if core_lib is None:
        print("imshark_core library not found in build dir; run cmake --build first.", file=sys.stderr)
        sys.exit(1)

    core_include = os.path.join(REPO_ROOT, "core", "src")
    cmd = [
        "c++", "-std=c++20", "-O2",
        f"-I{core_include}",
        driver_src,
        core_lib,
        "-o", driver_bin,
    ]
    # macOS needs framework
    if sys.platform == "darwin":
        cmd += ["-framework", "CoreFoundation"]

    print("Building bench driver:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return driver_bin


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--pcap", default=None)
    parser.add_argument("--packets", type=int, default=500_000)
    args = parser.parse_args()

    build_dir = os.path.join(REPO_ROOT, args.build_dir)
    n = args.packets
    k = n // 1000
    pcap = args.pcap or os.path.join(REPO_ROOT, "tests", "data", f"bench_{k}k.pcap")

    # Generate pcap if missing
    if not os.path.exists(pcap):
        generate_pcap(pcap, n)

    # Find or build bench driver
    driver = find_binary(build_dir, "bench_driver")
    if driver is None:
        print("bench_driver not found; attempting to build…")
        driver = build_driver(build_dir)

    print(f"\nBenchmark: {n:,} packets  pcap={pcap}")
    print("-" * 60)
    try:
        m = run_bench(driver, pcap)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    packets  = m.get("packets", n)
    load_ms  = m.get("load_ms", "?")
    rss_mb   = m.get("peak_rss_mb", "?")
    wall_s   = m.get("wall_s", "?")

    print(f"Packets loaded : {packets:>10,}")
    print(f"Load time      : {load_ms:>10} ms")
    print(f"Wall time      : {wall_s:>10} s")
    print(f"Peak RSS       : {rss_mb:>10} MB")
    if isinstance(load_ms, (int, float)) and load_ms > 0:
        rate = packets / (load_ms / 1000)
        print(f"Throughput     : {rate:>10,.0f} packets/s")
    print("-" * 60)


if __name__ == "__main__":
    main()

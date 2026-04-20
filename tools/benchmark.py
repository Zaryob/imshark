#!/usr/bin/env python3
"""ImShark performance benchmark: load a large capture, run one filter pass, report time and peak RSS.

Usage:
    python3 tools/benchmark.py [--build-dir build-bench] [--profile dns|mixed]
                               [--packets N | --size-mb MB] [--pcap FILE] [--filter EXPR] [--keep]

Steps (each is the plain command, printed before it runs):
  1. cmake -S . -B <build-dir> -DCMAKE_BUILD_TYPE=Release -DIMSHARK_BUILD_BENCH=ON -DIMSHARK_BUILD_TESTS=OFF
  2. cmake --build <build-dir> --target bench_driver     (links imshark_core like the application; needs the same
                                                          libraries, nothing else)
  3. tools/make_bench_pcap.py writes the capture into a temporary directory (or --pcap FILE, which is then kept
     if it already existed). The generated file is deleted afterwards unless --keep is given. Never commit it.
  4. <build-dir>/bench_driver <pcap> [--filter EXPR] prints one line:
       packets=N load_ms=T load_peak_rss_mb=R filter_ms=F filter_matched=M peak_rss_mb=R2

The numbers depend on the machine and on the profile; compare only runs of the same profile on the same machine.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))


def run(cmd, **kw):
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def build_driver(build_dir: str) -> str:
    run(["cmake", "-S", REPO_ROOT, "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release", "-DIMSHARK_BUILD_BENCH=ON",
         "-DIMSHARK_BUILD_TESTS=OFF"])
    run(["cmake", "--build", build_dir, "--target", "bench_driver", "--parallel"])
    for sub in ("", "Release"):
        p = os.path.join(build_dir, sub, "bench_driver.exe" if os.name == "nt" else "bench_driver")
        if os.path.isfile(p):
            return p
    sys.exit("bench_driver was not produced in " + build_dir)


def parse_line(text: str) -> dict:
    metrics = {}
    for token in text.split():
        if "=" in token:
            k, v = token.split("=", 1)
            metrics[k] = int(v) if v.lstrip("-").isdigit() else v
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", default="build-bench")
    ap.add_argument("--profile", choices=("dns", "mixed"), default="dns")
    ap.add_argument("--packets", type=int, default=None)
    ap.add_argument("--size-mb", type=float, default=None)
    ap.add_argument("--pcap", default=None, help="use/generate this file instead of a temporary one")
    ap.add_argument("--filter", default=None, help="display filter for the filter pass (driver default otherwise)")
    ap.add_argument("--keep", action="store_true", help="keep the generated capture")
    args = ap.parse_args()

    build_dir = args.build_dir if os.path.isabs(args.build_dir) else os.path.join(REPO_ROOT, args.build_dir)
    driver = build_driver(build_dir)

    tmp = None
    pcap = args.pcap
    generated = False
    if pcap is None:
        tmp = tempfile.mkdtemp(prefix="imshark-bench-")
        pcap = os.path.join(tmp, "bench.pcap")
    if not os.path.exists(pcap):
        gen = [sys.executable, os.path.join(SCRIPT_DIR, "make_bench_pcap.py"), "--output", pcap, "--profile", args.profile]
        if args.size_mb:
            gen += ["--size-mb", str(args.size_mb)]
        else:
            gen += ["--packets", str(args.packets or 500_000)]
        run(gen)
        generated = True
    try:
        cmd = [driver, pcap] + (["--filter", args.filter] if args.filter else [])
        print("$", " ".join(cmd), flush=True)
        t0 = time.monotonic()
        res = subprocess.run(cmd, capture_output=True, text=True)
        wall = time.monotonic() - t0
        if res.returncode != 0:
            sys.exit(f"bench_driver exited with {res.returncode}: {res.stderr.strip()}")
        print(res.stdout.strip())
        m = parse_line(res.stdout)
        size_mb = os.path.getsize(pcap) / 1024 / 1024
        print("-" * 60)
        print(f"File           : {size_mb:10.1f} MB")
        print(f"Packets        : {m.get('packets', '?'):>10}")
        print(f"Load time      : {m.get('load_ms', '?'):>10} ms")
        print(f"Filter pass    : {m.get('filter_ms', '?'):>10} ms ({m.get('filter_matched', '?')} matched)")
        print(f"Peak RSS       : {m.get('peak_rss_mb', '?'):>10} MB (after load: {m.get('load_peak_rss_mb', '?')} MB)")
        print(f"Wall time      : {wall:10.2f} s (includes process start)")
        if isinstance(m.get("load_ms"), int) and m["load_ms"] > 0:
            print(f"Load throughput: {m['packets'] / (m['load_ms'] / 1000):10,.0f} packets/s, "
                  f"{size_mb / (m['load_ms'] / 1000):.0f} MB/s")
        print("-" * 60)
    finally:
        if args.keep and generated:
            print("kept:", pcap)
        else:
            if generated:
                os.remove(pcap)
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()

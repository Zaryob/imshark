#!/usr/bin/env python3
"""Generates a large synthetic pcap file for performance benchmarking.

Usage:
    python3 tools/make_bench_pcap.py [--packets N] [--output FILE]

Defaults: 500 000 packets, tests/data/bench_500k.pcap

Each packet is a minimal Ethernet/IPv4/UDP/DNS query (~74 bytes on wire).
The file can be used with the benchmark script:
    python3 tools/benchmark.py [--build-dir build]
"""
import argparse
import struct
import sys
import os
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.join(SCRIPT_DIR, "..")


def hexb(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def pcap_header(snaplen: int = 65535, network: int = 1) -> bytes:
    # little-endian, magic=0xa1b2c3d4, ver 2.4, microsecond resolution
    return struct.pack("<IHHiIII", 0xa1B2C3D4, 2, 4, 0, 0, snaplen, network)


def pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    n = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + data


# A fixed minimal DNS query carried over UDP/IPv4/Ethernet
# Ethernet  : dst=ff:ff:ff:ff:ff:ff  src=00:11:22:33:44:55  EtherType=0x0800
# IPv4      : IHL=20, TTL=64, proto=17 (UDP), src=10.0.0.1, dst=8.8.8.8
# UDP       : sport=50000, dport=53
# DNS       : query for example.com A
_ETH   = hexb("ffffffffffff 001122334455 0800")
_DNS   = hexb("1234 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001")
_UDP_LEN = 8 + len(_DNS)
_UDP   = struct.pack(">HHHH", 50000, 53, _UDP_LEN, 0) + _DNS
_IPV4_PAYLOAD = _UDP
_IP_LEN = 20 + len(_IPV4_PAYLOAD)
_IPV4  = (hexb("4500") +
          struct.pack(">HHHBBHbbbb", _IP_LEN, 0x1234, 0x4000, 64, 17, 0,
                      10, 0, 0, 1) +
          hexb("08080808") +
          _IPV4_PAYLOAD)
PACKET = _ETH + _IPV4


def make_bench_pcap(path: str, n_packets: int) -> None:
    ts_sec  = 1_700_000_000
    ts_usec = 0

    print(f"Writing {n_packets:,} packets to {path} …", flush=True)
    t0 = time.monotonic()
    with open(path, "wb") as f:
        f.write(pcap_header())
        for i in range(n_packets):
            f.write(pcap_record(ts_sec, ts_usec, PACKET))
            ts_usec += 1000
            if ts_usec >= 1_000_000:
                ts_usec -= 1_000_000
                ts_sec  += 1

    elapsed = time.monotonic() - t0
    size_mb = os.path.getsize(path) / 1024 / 1024
    print(f"Done: {size_mb:.1f} MB in {elapsed:.2f}s", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=500_000,
                        help="Number of packets to generate (default: 500 000)")
    parser.add_argument("--output", default=None,
                        help="Output file path (default: tests/data/bench_<N>k.pcap)")
    args = parser.parse_args()

    k = args.packets // 1000
    out = args.output or os.path.join(REPO_ROOT, "tests", "data",
                                      f"bench_{k}k.pcap")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    make_bench_pcap(out, args.packets)


if __name__ == "__main__":
    main()

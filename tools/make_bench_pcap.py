#!/usr/bin/env python3
"""Generates a large synthetic pcap file for performance benchmarking.

Usage:
    python3 tools/make_bench_pcap.py --output FILE [--profile dns|mixed] [--packets N | --size-mb MB]

Profiles
  dns    (default) every packet is the same Ethernet/IPv4/UDP/DNS query (83 bytes on the wire). One flow, no
         payload variety: it measures the per-packet cost of the load pass and nothing else.
  mixed  many flows: TCP segments (2000 connections, advancing sequence numbers, payload of 0..1448 random bytes),
         UDP DNS queries with varying names and ids, and 512 byte UDP datagrams to varying ports. The payloads are
         random bytes, so apart from DNS no application dissector produces a tree; TCP reassembly and the
         per-flow state are exercised. It is still synthetic traffic, not a substitute for a real capture.

The output goes wherever --output says; generated captures must never be committed (tests/data/bench_*.pcap and
*.pcap under a scratch directory are the places to use; tools/benchmark.py deletes its file after measuring).
"""
from __future__ import annotations

import argparse
import os
import random
import struct
import sys
import time


def hexb(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def pcap_header(snaplen: int = 65535, network: int = 1) -> bytes:
    # little-endian, magic=0xa1b2c3d4, ver 2.4, microsecond resolution
    return struct.pack("<IHHiIII", 0xa1B2C3D4, 2, 4, 0, 0, snaplen, network)


def pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    n = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + data


_ETH = hexb("ffffffffffff 001122334455 0800")


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, ident: int) -> bytes:
    total = 20 + len(payload)
    # checksums are left zero: the load pass only reports them, it does not skip the packet
    return (b"\x45\x00" + struct.pack(">HHHBBH", total, ident & 0xFFFF, 0x4000, 64, proto, 0) + src + dst + payload)


# dns profile: one fixed query for example.com A
_DNS = hexb("1234 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001")
_UDP = struct.pack(">HHHH", 50000, 53, 8 + len(_DNS), 0) + _DNS
PACKET = _ETH + ipv4(bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]), 17, _UDP, 0x1234)


def dns_packets(n):
    for _ in range(n):
        yield PACKET


def mixed_packets(n, seed=1):
    rng = random.Random(seed)
    pool = rng.randbytes(4096)
    flows = []
    for i in range(2000):
        flows.append([bytes([10, 1, i >> 8 & 0xFF, i & 0xFF]), bytes([192, 168, rng.randrange(256), rng.randrange(1, 255)]),
                      rng.randrange(1024, 65535), rng.choice((80, 443, 8080, 5001, 22, 3306)),
                      rng.randrange(1 << 32), rng.randrange(1 << 32)])
    for i in range(n):
        r = rng.random()
        if r < 0.70:                                   # TCP segment on one of the connections
            f = flows[rng.randrange(len(flows))]
            plen = rng.choice((0, 0, 64, 512, 1448, 1448, 1448))
            off = rng.randrange(len(pool) - 1448)
            payload = pool[off:off + plen]
            flags = 0x18 if plen else 0x10             # PSH|ACK or ACK
            tcp = struct.pack(">HHIIBBHHH", f[2], f[3], f[4], f[5], 5 << 4, flags, 65535, 0, 0) + payload
            f[4] = (f[4] + plen) & 0xFFFFFFFF
            yield _ETH + ipv4(f[0], f[1], 6, tcp, i)
        elif r < 0.90:                                 # DNS query with a varying name and id
            label = b"h%d" % rng.randrange(100000)
            dns = struct.pack(">HHHHHH", rng.randrange(65536), 0x0100, 1, 0, 0, 0) + bytes([len(label)]) + label \
                + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
            udp = struct.pack(">HHHH", rng.randrange(1024, 65535), 53, 8 + len(dns), 0) + dns
            yield _ETH + ipv4(bytes([10, 2, rng.randrange(256), rng.randrange(256)]), bytes([8, 8, 8, 8]), 17, udp, i)
        else:                                          # 512 byte UDP datagram
            off = rng.randrange(len(pool) - 512)
            udp = struct.pack(">HHHH", rng.randrange(1024, 65535), rng.randrange(1024, 65535), 8 + 512, 0) + pool[off:off + 512]
            yield _ETH + ipv4(bytes([10, 3, rng.randrange(256), rng.randrange(256)]),
                              bytes([172, 16, rng.randrange(256), rng.randrange(1, 255)]), 17, udp, i)


def make_bench_pcap(path: str, profile: str, n_packets: int | None, size_mb: float | None) -> None:
    ts_sec, ts_usec = 1_700_000_000, 0
    gen = {"dns": dns_packets, "mixed": mixed_packets}[profile]
    limit_bytes = int(size_mb * 1024 * 1024) if size_mb else None
    # with a size target the packet count is open ended: the generators are fed a count large enough and cut off
    count = n_packets if n_packets else 100_000_000
    print(f"Writing {profile} profile to {path} ...", flush=True)
    t0 = time.monotonic()
    written = 0
    packets = 0
    with open(path, "wb") as f:
        f.write(pcap_header())
        written = 24
        buf = []
        for data in gen(count):
            buf.append(pcap_record(ts_sec, ts_usec, data))
            written += 16 + len(data)
            packets += 1
            ts_usec += 1000
            if ts_usec >= 1_000_000:
                ts_usec -= 1_000_000
                ts_sec += 1
            if len(buf) >= 20000:
                f.write(b"".join(buf))
                buf.clear()
            if limit_bytes and written >= limit_bytes:
                break
        f.write(b"".join(buf))
    elapsed = time.monotonic() - t0
    print(f"Done: {packets:,} packets, {os.path.getsize(path) / 1024 / 1024:.1f} MB in {elapsed:.2f}s", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packets", type=int, default=None, help="Number of packets (default 500 000 without --size-mb)")
    parser.add_argument("--size-mb", type=float, default=None, help="Stop at about this file size instead of a packet count")
    parser.add_argument("--profile", choices=("dns", "mixed"), default="dns")
    parser.add_argument("--output", required=True, help="Output file (outside the repository or ignored by git)")
    args = parser.parse_args()
    if args.packets and args.size_mb:
        parser.error("use either --packets or --size-mb")
    n = args.packets if args.packets or args.size_mb else 500_000
    make_bench_pcap(args.output, args.profile, n, args.size_mb)


if __name__ == "__main__":
    main()

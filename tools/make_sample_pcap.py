#!/usr/bin/env python3
"""Generates tests/data/sample.pcap: a small, deterministic capture that exercises the dissectors.

Usage: python3 tools/make_sample_pcap.py [output.pcap]
"""
import struct
import sys

A_MAC, B_MAC = bytes.fromhex("001122334455"), bytes.fromhex("aabbccddeeff")
A_IP, B_IP, DNS_IP = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), bytes([8, 8, 8, 8])


def eth(dst, src, etype, payload, vlan=None):
    tag = struct.pack(">HH", 0x8100, vlan) if vlan is not None else b""
    return dst + src + tag + struct.pack(">H", etype) + payload


def ipv4(src, dst, proto, payload, flags_frag=0x4000):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, flags_frag, 64, proto, 0, src, dst)
    return hdr + payload


def tcp(sp, dp, seq, ack, flags, payload=b"", options=b""):
    off = (20 + len(options)) // 4
    return struct.pack(">HHIIBBHHH", sp, dp, seq, ack, off << 4, flags, 29200, 0, 0) + options + payload


def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def arp(op, smac, sip, tmac, tip):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + smac + sip + tmac + tip


SYN_OPTS = struct.pack(">BBH", 2, 4, 1460) + b"\x01" + bytes([3, 3, 7]) + bytes([4, 2]) + bytes([8, 10]) + struct.pack(">II", 1, 0)

frames = [
    eth(b"\xff" * 6, A_MAC, 0x0806, arp(1, A_MAC, A_IP, b"\0" * 6, B_IP)),
    eth(A_MAC, B_MAC, 0x0806, arp(2, B_MAC, B_IP, A_MAC, A_IP)),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 1, struct.pack(">BBHHH", 8, 0, 0, 1, 1) + b"ping")),
    eth(A_MAC, B_MAC, 0x0800, ipv4(B_IP, A_IP, 1, struct.pack(">BBHHH", 0, 0, 0, 1, 1) + b"ping")),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, DNS_IP, 17, udp(51000, 53, struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + dns_name("example.com") + struct.pack(">HH", 1, 1)))),
    eth(A_MAC, B_MAC, 0x0800, ipv4(DNS_IP, A_IP, 17, udp(53, 51000, struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + dns_name("example.com") + struct.pack(">HH", 1, 1) + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])))),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 6, tcp(40000, 80, 1000, 0, 0x02, options=SYN_OPTS))),
    eth(A_MAC, B_MAC, 0x0800, ipv4(B_IP, A_IP, 6, tcp(80, 40000, 9000, 1001, 0x12, options=SYN_OPTS))),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 6, tcp(40000, 80, 1001, 9001, 0x10))),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 6, tcp(40000, 80, 1001, 9001, 0x18, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))),
    eth(A_MAC, B_MAC, 0x0800, ipv4(B_IP, A_IP, 6, tcp(80, 40000, 9001, 1038, 0x11))),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 6, tcp(40000, 25, 500, 0, 0x18, payload=b"EHLO imshark\r\n"))),
    eth(B_MAC, A_MAC, 0x86DD, struct.pack(">IHBB", 0x60000000, 8 + 4, 17, 64) + bytes.fromhex("20010db8000000000000000000000001") + bytes.fromhex("20010db8000000000000000000000002") + udp(1234, 5678, b"ipv6")),
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 17, udp(1000, 2000, b"vlan tagged")), vlan=100),
    eth(B_MAC, A_MAC, 0x88CC, b"\x02\x07lldp-ish"),                      # unknown EtherType
    eth(B_MAC, A_MAC, 0x0800, ipv4(A_IP, B_IP, 6, tcp(1, 2, 3, 4, 0x10)))[:40],   # truncated TCP header
]

out = sys.argv[1] if len(sys.argv) > 1 else "tests/data/sample.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        f.write(struct.pack("<IIII", 1_700_000_000 + i // 4, (i % 4) * 250_000, len(frame), len(frame)) + frame)
print(f"wrote {out}: {len(frames)} packets")

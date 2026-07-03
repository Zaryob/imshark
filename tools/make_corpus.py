#!/usr/bin/env python3
"""Builds the regression corpus: small synthetic captures for edge cases + tests/corpus/manifest.json.

  python3 tools/make_corpus.py                       # writes tests/corpus/*.pcap* and the manifest
  python3 tools/make_corpus.py --real-dir DIR        # also records real captures found in DIR (optional entries)

The synthetic files are generated deterministically, and their expectations are written here by construction
(not copied from ImShark's output). Real captures are NOT stored in the repository: the manifest records where
they come from (URL), their SHA-256 and what is expected; the test runs them when IMSHARK_CORPUS_DIR points at a
directory that has them and skips them otherwise. For real files the packet count is counted independently by
this script; the protocol histogram is a snapshot of ImShark's output (marked as such).
"""
import argparse, datetime, hashlib, json, os, struct, sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "corpus")

# ---------------------------------------------------------------------------------------------- builders
def hexb(s): return bytes.fromhex(s.replace(" ", ""))

def pcap(frames, network=1, big=False, nano=False, snaplen=65535, times=None):
    e = ">" if big else "<"
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, snaplen, network)
    for i, f in enumerate(frames):
        sec, frac = times[i] if times else (1700000000 + i, 0)
        out += struct.pack(e + "IIII", sec, frac, len(f), len(f)) + f
    return out

def block(t, body, e="<"):
    total = 12 + len(body)
    return struct.pack(e + "II", t, total) + body + struct.pack(e + "I", total)

def opt(code, value, e="<"):
    return struct.pack(e + "HH", code, len(value)) + value + b"\0" * ((4 - len(value) % 4) % 4)

def shb(e="<"):
    return block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)

def idb(link=1, tsresol=None, tsoffset=None, fcs_bits=None, e="<"):
    body = struct.pack(e + "HHI", link, 0, 65535)
    if tsresol is not None: body += opt(9, bytes([tsresol]), e)
    if tsoffset is not None: body += opt(14, struct.pack(e + "q", tsoffset), e)
    if fcs_bits is not None: body += opt(13, bytes([fcs_bits]), e)
    body += struct.pack(e + "I", 0)
    return block(1, body, e)

def epb(iface, ticks, frame, e="<"):
    pad = b"\0" * ((4 - len(frame) % 4) % 4)
    return block(6, struct.pack(e + "IIIII", iface, ticks >> 32, ticks & 0xffffffff, len(frame), len(frame)) + frame + pad, e)

def legacy_pb(iface, ticks, frame, e="<"):
    pad = b"\0" * ((4 - len(frame) % 4) % 4)
    return block(2, struct.pack(e + "HHIIII", iface, 0, ticks >> 32, ticks & 0xffffffff, len(frame), len(frame)) + frame + pad, e)

ARP = hexb("ffffffffffff 001122334455 0806 0001 0800 06 04 0001 001122334455 0a000001 000000000000 0a000002")
MAC = "001122334455 aabbccddeeff"

def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload

def ipv4(proto, payload, src="0a000001", dst="0a000002", ident=0x1234, flags_frag=0x4000, ttl=64):
    return hexb("4500") + struct.pack(">HHHBBH", 20 + len(payload), ident, flags_frag, ttl, proto, 0) + hexb(src) + hexb(dst) + payload

def eth(etype, payload): return hexb(MAC) + struct.pack(">H", etype) + payload

DNS_QUERY = hexb("1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001")
DGRAM = udp(50000, 53, DNS_QUERY)                                    # 37 bytes

def frag6(payload, off, n, ident, more, nxt=0x11, src="20010db8000000000000000000000001"):
    fh = bytes([nxt, 0]) + struct.pack(">HI", ((off // 8) << 3) | (1 if more else 0), ident)
    body = fh + payload[off:off + n]
    ip6 = hexb("60000000") + struct.pack(">HBB", len(body), 44, 64) + hexb(src) + hexb("20010db8000000000000000000000002")
    return eth(0x86DD, ip6 + body)

def frag4(payload, off, n, ident, more, proto=0x11):
    return eth(0x0800, ipv4(proto, payload[off:off + n], ident=ident, flags_frag=((off // 8) | (0x2000 if more else 0))))

# Sun snoop, RFC 1761 (big endian): 16 byte header "snoop\0\0\0", version, datalink type; then records of
# original length, included length, record length (24 + data + padding to a multiple of 4), cumulative drops,
# seconds, microseconds, data, padding.
def snoop(frames, datalink=4, times=None, version=2):
    out = b"snoop\0\0\0" + struct.pack(">II", version, datalink)
    for i, f in enumerate(frames):
        sec, usec = times[i] if times else (1700000000 + i, 0)
        pad = b"\0" * ((4 - len(f) % 4) % 4)
        out += struct.pack(">IIIIII", len(f), len(f), 24 + len(f) + len(pad), 0, sec, usec) + f + pad
    return out

# Microsoft Network Monitor 2.x (little endian): 72 byte header (magic "GMBU", minor, major, MAC type, SYSTEMTIME of the
# capture start, then offset/length pairs of the frame table, user data, comment, statistics, network info and
# conversation statistics), the frame records (u64 microseconds since the start, original length, included length,
# data), and at the end the frame table: one absolute u32 file offset per frame, in capture order.
def netmon(frames, mac=1, start=1700000000, millis=0, deltas=None, minor=1, major=2, user_data=b"", order=None):
    t = datetime.datetime.fromtimestamp(start, datetime.timezone.utc)
    systemtime = struct.pack("<8H", t.year, t.month, (t.weekday() + 1) % 7, t.day, t.hour, t.minute, t.second, millis)
    body = user_data                                   # sits between the header and the first frame record
    offsets = []
    pos = 72 + len(body)
    for i, f in enumerate(frames):
        d = deltas[i] if deltas else i * 1000000
        offsets.append(pos)
        rec = struct.pack("<QII", d, len(f), len(f)) + f
        body += rec
        pos += len(rec)
    table = b"".join(struct.pack("<I", offsets[i]) for i in (order if order is not None else range(len(frames))))
    hdr = b"GMBU" + bytes([minor, major]) + struct.pack("<H", mac) + systemtime
    hdr += struct.pack("<12I", pos, len(table), 72 if user_data else 0, len(user_data), 0, 0, 0, 0, 0, 0, 0, 0)
    return hdr + body + table

# ------------------------------------------------------------------------------------- synthetic corpus
SYNTHETIC = []

def add(name, data, fmt, link_types, packets, protocols, facts=None, message=None, malformed=0, note=""):
    SYNTHETIC.append(dict(name=name, data=data, format=fmt, link_types=link_types, packets=packets,
                          protocols=protocols, facts=facts or [], message=message, malformed=malformed, note=note))

add("arp-little-endian.pcap", pcap([ARP, ARP]), "pcap", [1], 2, {"ARP": 2}, note="the smallest valid capture")
add("arp-big-endian.pcap", pcap([ARP], big=True), "pcap", [1], 1, {"ARP": 1}, note="byte-swapped pcap")
add("arp-nanosecond.pcap", pcap([ARP, ARP], nano=True, times=[(1700000000, 0), (1700000001, 500000000)]), "pcap", [1], 2, {"ARP": 2},
    facts=[{"packet": 2, "time_relative": 1.5}], note="nanosecond precision")
add("ethernet-fcs.pcap", pcap([ARP + hexb("deadbeef")], network=0x50000001), "pcap", [1], 1, {"ARP": 1},
    facts=[{"packet": 1, "fcs_length": 4}], note="FCS flag + length in the network field: the 4 trailing bytes are not payload")
add("truncated-last-record.pcap", pcap([ARP, ARP])[:-9], "pcap", [1], 1, {"ARP": 1}, message="Truncated", note="a damaged tail keeps the earlier packets")
add("pcapng-legacy-packet-block.pcapng", shb() + idb() + legacy_pb(0, 1000000, ARP), "pcapng", [1], 1, {"ARP": 1}, note="obsolete block type 2")
add("pcapng-two-interfaces-tsoffset.pcapng",
    shb() + idb(tsresol=6, tsoffset=1000) + idb(tsresol=6, tsoffset=1100) + epb(0, 5000000, ARP) + epb(1, 5000000, ARP), "pcapng", [1], 2, {"ARP": 2},
    facts=[{"packet": 2, "time_relative": 100.0}], note="if_tsoffset puts the clocks of two interfaces in line")
add("pcapng-undefined-interface.pcapng", shb() + idb() + epb(0, 1000000, ARP) + epb(9, 2000000, ARP), "pcapng", [1, 4294967295], 2, {"ARP": 1, "Unknown": 1},
    message="no Interface Description Block", note="a packet of an interface nobody defined is kept but not decoded")
add("pcapng-big-endian-fcs-bits.pcapng", shb(">") + idb(fcs_bits=32, e=">") + epb(0, 1000000, ARP + hexb("cafebabe"), ">"), "pcapng", [1], 1, {"ARP": 1},
    facts=[{"packet": 1, "fcs_length": 4}], note="if_fcslen is in bits")
add("ipv6-fragments-out-of-order.pcap", pcap([frag6(DGRAM, 32, 5, 0xCAFEBABE, False), frag6(DGRAM, 0, 16, 0xCAFEBABE, True), frag6(DGRAM, 16, 16, 0xCAFEBABE, True)]),
    "pcap", [1], 3, {"IPv6": 2, "DNS": 1},
    facts=[{"packet": 3, "protocol": "DNS", "info_contains": "example.com"}, {"packet": 1, "reassembled_in": 3}, {"packet": 2, "reassembled_in": 3}],
    note="whatever order the fragments arrive in, the packet that arrives last (3) completes the datagram")
add("ipv6-non-first-fragment.pcap", pcap([frag6(DGRAM, 16, 16, 0x77, True)]), "pcap", [1], 1, {"IPv6": 1},
    facts=[{"packet": 1, "protocol": "IPv6", "info_contains": "Fragmented IPv6 protocol"}],
    note="a middle fragment alone must never be read as a UDP header")
add("ipv4-fragments.pcap", pcap([frag4(DGRAM, 0, 16, 7, True), frag4(DGRAM, 16, 16, 7, True), frag4(DGRAM, 32, 5, 7, False)]),
    "pcap", [1], 3, {"IPv4": 2, "DNS": 1}, facts=[{"packet": 3, "protocol": "DNS"}, {"packet": 1, "reassembled_in": 3}])
add("ethernet-vlan-qinq.pcap", pcap([eth(0x88a8, struct.pack(">H", 100) + struct.pack(">H", 0x8100) + struct.pack(">H", 200) + struct.pack(">H", 0x0800) + ipv4(17, udp(1000, 2000, b"vlan")))]),
    "pcap", [1], 1, {"UDP": 1}, note="two VLAN tags in front of the IP header")
add("linux-cooked-udp.pcap", pcap([hexb("0000 0001 0006 001122334455 0000 0800") + ipv4(17, udp(1000, 2000, b"sll"))], network=113),
    "pcap", [113], 1, {"UDP": 1})

DNS_FRAME = eth(0x0800, ipv4(17, DGRAM))                              # 71 bytes: the record needs padding
add("snoop-ethernet.snoop", snoop([ARP, DNS_FRAME, ARP], times=[(1700000000, 0), (1700000001, 250000), (1700000003, 0)]),
    "snoop", [1], 3, {"ARP": 2, "DNS": 1},
    facts=[{"packet": 2, "protocol": "DNS", "info_contains": "example.com", "time_relative": 1.25}, {"packet": 3, "time_relative": 3.0}],
    note="RFC 1761 version 2, datalink type 4 (Ethernet); the 42 and 71 byte frames are padded to 4 bytes")
add("snoop-token-ring.snoop", snoop([hexb("1040 00" + "00" * 29)], datalink=2), "snoop", [6], 1, {"Unknown": 1},
    facts=[{"packet": 1, "protocol": "Unknown", "info_contains": "Unsupported link type 6"}],
    note="datalink type 2 (IEEE 802.5) maps to the Token Ring link type, which has no dissector")
add("snoop-truncated-last-record.snoop", snoop([ARP, DNS_FRAME])[:-20], "snoop", [1], 1, {"ARP": 1}, message="Truncated or corrupt packet 2",
    note="a damaged tail keeps the earlier records")

add("netmon-ethernet.cap", netmon([ARP, DNS_FRAME, ARP], deltas=[0, 1250000, 3000000], millis=500, user_data=b"user data area."), "netmon", [1], 3, {"ARP": 2, "DNS": 1},
    facts=[{"packet": 2, "protocol": "DNS", "info_contains": "example.com", "time_relative": 1.25}, {"packet": 3, "time_relative": 3.0}],
    note="Network Monitor 2.1, MAC type 1 (Ethernet); a user data area sits between the header and the first frame, the frame table at the end locates the frames")
add("netmon-frame-table-order.cap", netmon([DNS_FRAME, ARP], deltas=[5000000, 2000000], order=[1, 0]), "netmon", [1], 2, {"ARP": 1, "DNS": 1},
    facts=[{"packet": 1, "protocol": "ARP"}, {"packet": 2, "protocol": "DNS", "time_relative": 3.0}],
    note="the frame table, not the physical order, is the capture order: the ARP frame is stored second but is packet 1")
add("netmon-atm-media.cap", netmon([hexb("00" * 24)], mac=4), "netmon", [147], 1, {"Unknown": 1},
    facts=[{"packet": 1, "info_contains": "Unsupported link type 147"}], message="shown as raw data",
    note="MAC type 4 (ATM) has no mapping: the frame is kept as raw data and the load says so")

# ------------------------------------------------------------------------------------------ real captures
WIKI = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/"
REAL = [
    # name, source url, protocols (snapshot of ImShark), facts, limitation
    ("dhcp.pcap", WIKI + "dhcp.pcap", {"DHCP": 4}, [{"packet": 1, "info_contains": "DHCP Discover"}], None),
    ("dhcp-nanosecond.pcap", WIKI + "dhcp-nanosecond.pcap", {"DHCP": 4}, [], None),
    ("NTP_sync.pcap", WIKI + "NTP_sync.pcap", {"DNS": 2, "NTP": 30}, [{"packet": 1, "info_contains": "us.pool.ntp.org"}], None),
    ("ipv4frags.pcap", WIKI + "ipv4frags.pcap", {"ICMP": 2, "IPv4": 1},
     [{"packet": 1, "info_contains": "Fragmented IP protocol (proto=ICMP 1, off=0, ID=0xb5d0)"}, {"packet": 1, "reassembled_in": 2},
      {"packet": 2, "info_contains": "Echo (ping) request"}], None),
    ("http.cap", "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap", {"DNS": 2, "HTTP": 5, "TCP": 36},
     [{"packet": 4, "info_contains": "GET /download.html HTTP/1.1"}, {"packet": 6, "info_contains": "HTTP/1.1 200 OK"}],
     "HTTP messages are not reassembled across TCP segments yet (v0.7.2)"),
    ("dns_port.pcap", WIKI + "dns_port.pcap", {"UDP": 2}, [], "DNS on a non-standard port is not recognised yet (v0.7.2 Decode As)"),
    ("PRIV_bootp-both_overload.pcap", WIKI + "PRIV_bootp-both_overload.pcap", {"DHCP": 1}, [], "DHCP option overload (sname/file) is not scanned yet (v0.7.2)"),
    ("PRIV_bootp-both_overload_empty-no_end.pcap", WIKI + "PRIV_bootp-both_overload_empty-no_end.pcap", {"DHCP": 1}, [], "DHCP option overload is not scanned yet (v0.7.2)"),
    ("http_PPI.cap", "https://wiki.wireshark.org/uploads/e8cebabd278b76e3bc9edbd484c4d293/http_PPI.cap", {"Unknown": 140}, [], "link type 192 (PPI / 802.11) is not supported yet (v0.9)"),
]

# --------------------------------------------------------------------------------- independent file facts
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def count_packets(path):
    """Counts the packets of a classic pcap file independently of ImShark."""
    d = open(path, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    if magic in (0xa1b2c3d4, 0xa1b23c4d): e = "<"
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1): e = ">"
    else: return None
    network = struct.unpack(e + "I", d[20:24])[0] & 0xFFFF
    pos, n = 24, 0
    while pos + 16 <= len(d):
        incl = struct.unpack(e + "I", d[pos + 8:pos + 12])[0]
        if pos + 16 + incl > len(d): break
        pos += 16 + incl
        n += 1
    return n, network

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-dir", help="directory with real captures to record (see REAL in this script)")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    entries = []
    for s in SYNTHETIC:
        path = os.path.join(OUT, s["name"])
        open(path, "wb").write(s["data"])
        entries.append({"file": s["name"], "kind": "synthetic", "source": "tools/make_corpus.py", "sha256": sha256(path), "size": os.path.getsize(path),
                        "format": s["format"], "link_types": s["link_types"], "packets": s["packets"], "protocols": s["protocols"],
                        "malformed": s["malformed"], "facts": s["facts"], "expectation": "by construction", "note": s["note"]}
                       | ({"message_contains": s["message"]} if s["message"] else {}))

    real_dir = args.real_dir
    for name, url, protocols, facts, limitation in REAL:
        entry = {"file": name, "kind": "real", "optional": True, "source": url, "protocols": protocols, "malformed": 0, "facts": facts,
                 "expectation": "packet count counted independently; protocol histogram is a snapshot of ImShark's output"}
        if limitation: entry["known_limitation"] = limitation
        path = os.path.join(real_dir, name) if real_dir else None
        if path and os.path.exists(path):
            entry["sha256"], entry["size"] = sha256(path), os.path.getsize(path)
            info = count_packets(path)
            if info is None: sys.exit("not a classic pcap file: " + path)
            entry["packets"], network = info
            entry["format"], entry["link_types"] = "pcap", [network]
        else:
            # keep what an earlier run recorded: the manifest must not lose entries when the files are absent
            old = {}
            mp = os.path.join(OUT, "manifest.json")
            if os.path.exists(mp):
                old = {e["file"]: e for e in json.load(open(mp))["entries"]}.get(name, {})
            for k in ("sha256", "size", "packets", "format", "link_types"):
                if k in old: entry[k] = old[k]
            if "sha256" not in entry: sys.exit("no recorded data for %s: run once with --real-dir" % name)
        entries.append(entry)

    manifest = {"description": "Regression corpus for ImShark. 'synthetic' files live in this directory; 'real' ones are optional and "
                               "found through the IMSHARK_CORPUS_DIR environment variable (never downloaded by the tests).",
                "entries": entries}
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("wrote %d synthetic files and a manifest with %d entries" % (len(SYNTHETIC), len(entries)))

if __name__ == "__main__":
    main()

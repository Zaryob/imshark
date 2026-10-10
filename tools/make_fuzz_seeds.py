#!/usr/bin/env python3
"""Builds the seed corpora and the generated dictionary of the fuzz harnesses (docs/FUZZING.md).

  python3 tools/make_fuzz_seeds.py            # rewrites fuzz/corpus/<harness>/ and fuzz/dict/filter.dict

Everything is derived from files that are already in the repository, deterministically (running it twice changes nothing):

  fuzz_capture_file      the synthetic captures of tests/corpus (made by tools/make_corpus.py), tests/data/sample.pcap(.gz)
                         (tools/make_sample_pcap.py) and the TLS fixtures of tests/data/tls (tools/make_tls_fixtures.py)
  fuzz_packet            single frames cut out of those pcap / pcapng files: 2 selector bytes (link type, options) + frame
  fuzz_packet_sequence   all frames of one file as  selector bytes + (uint16 length, frame)*
  fuzz_filter            the expressions of the string literals in tests/test_filter.cpp
  fuzz_gzip              the gzip files of tests/data/gzip (the large ones are left out to keep the corpus small)

The link type selector is the index into fuzz::kLinkTypes (fuzz/fuzz_common.h), which this script reads from there.
"""
import hashlib
import os
import re
import shutil
import struct
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FUZZ = os.path.join(ROOT, "fuzz")
MAX_FRAMES_PER_FILE = 48
MAX_FRAME_SEEDS_PER_FILE = 6
MAX_SEQUENCE_BYTES = 16 * 1024


def read_link_table():
    text = open(os.path.join(FUZZ, "fuzz_common.h")).read()
    body = re.search(r"kLinkTypes\[\]\s*=\s*\{(.*?)\};", text, re.S).group(1)
    table = []
    for line in body.splitlines():
        line = line.split("//")[0].strip().rstrip(",")
        if line:
            table.append(int(line.rstrip("u"), 0))
    return table


# ------------------------------------------------------------------------------------------------ capture readers
def pcap_frames(data):
    """(link type, [frames]) of a classic pcap file; None if it is not one."""
    magics = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    e = magics.get(data[:4])
    if e is None or len(data) < 24:
        return None
    link = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
    frames, pos = [], 24
    while pos + 16 <= len(data):
        incl = struct.unpack(e + "I", data[pos + 8:pos + 12])[0]
        if pos + 16 + incl > len(data):
            break
        frames.append(data[pos + 16:pos + 16 + incl])
        pos += 16 + incl
    return link, frames


def pcapng_frames(data):
    """(link type of the first interface, [frames of that link type]) of a pcapng file; None if it is not one."""
    if data[:4] != b"\x0a\x0d\x0d\x0a" or len(data) < 12:
        return None
    e = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    links, frames, pos = [], [], 0
    while pos + 12 <= len(data):
        kind, total = struct.unpack(e + "II", data[pos:pos + 8])
        if total < 12 or pos + total > len(data):
            break
        body = data[pos + 8:pos + total - 4]
        if kind == 1 and len(body) >= 8:
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif kind == 6 and len(body) >= 20:
            iface, _, _, caplen, _ = struct.unpack(e + "IIIII", body[:20])
            if iface < len(links):
                frames.append((links[iface], body[20:20 + caplen]))
        pos += total
    if not links:
        return None
    first = links[0]
    return first, [f for (l, f) in frames if l == first]


def frames_of(path):
    data = open(path, "rb").read()
    return pcap_frames(data) or pcapng_frames(data)


# ------------------------------------------------------------------------------------------------ writers
def reset(directory):
    shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory)


def write(directory, name, data):
    with open(os.path.join(directory, name), "wb") as f:
        f.write(data)


def digest(data):
    return hashlib.sha256(data).hexdigest()[:10]


def sources():
    out = []
    for folder in ("tests/corpus", "tests/data"):
        for root, _, names in os.walk(os.path.join(ROOT, folder)):
            for n in sorted(names):
                if n.endswith((".pcap", ".pcapng", ".cap", ".snoop", ".erf", ".iptrace")) or n == "sample.pcap.gz":
                    out.append(os.path.join(root, n))
    return sorted(out)


def capture_seeds():
    d = os.path.join(FUZZ, "corpus", "fuzz_capture_file")
    reset(d)
    for path in sources():
        write(d, os.path.basename(path), open(path, "rb").read())


def packet_seeds(table):
    dp, ds = os.path.join(FUZZ, "corpus", "fuzz_packet"), os.path.join(FUZZ, "corpus", "fuzz_packet_sequence")
    reset(dp)
    reset(ds)
    for path in sources():
        parsed = frames_of(path)
        if not parsed:
            continue
        link, frames = parsed
        if link not in table or not frames:
            continue
        selector = table.index(link)
        base = os.path.basename(path).replace(".", "-")
        seen = set()
        for frame in frames:
            if len(frame) in (0,) or frame in seen or len(seen) >= MAX_FRAME_SEEDS_PER_FILE:
                continue
            seen.add(frame)
            write(dp, "%s-%s" % (base, digest(frame)), bytes([selector, 0]) + frame)
        sequence = bytearray([selector, 0])
        for frame in frames[:MAX_FRAMES_PER_FILE]:
            if len(sequence) + 2 + len(frame) > MAX_SEQUENCE_BYTES:
                break
            sequence += struct.pack("<H", len(frame)) + frame
        write(ds, base, bytes(sequence))


def filter_seeds():
    d = os.path.join(FUZZ, "corpus", "fuzz_filter")
    reset(d)
    text = open(os.path.join(ROOT, "tests", "test_filter.cpp"), encoding="utf-8").read()
    expressions = set()
    for m in re.finditer(r'\b(?:match|compile|ok|bad|matchWith|filterOf)\(\s*"((?:[^"\\]|\\.)*)"', text):
        try:
            expr = bytes(m.group(1), "utf-8").decode("unicode_escape").encode("latin-1", "ignore")
        except Exception:
            continue
        if 0 < len(expr) <= 200:
            expressions.add(expr)
    for expr in sorted(expressions):
        write(d, "expr-" + digest(expr), expr)


def gzip_seeds():
    d = os.path.join(FUZZ, "corpus", "fuzz_gzip")
    reset(d)
    src = os.path.join(ROOT, "tests", "data", "gzip")
    for n in sorted(os.listdir(src)):
        path = os.path.join(src, n)
        if n.endswith(".gz") and os.path.getsize(path) <= 4096:
            write(d, n, open(path, "rb").read())
    write(d, "sample-pcap.gz", open(os.path.join(ROOT, "tests", "data", "sample.pcap.gz"), "rb").read())


def filter_dictionary():
    names = []
    for line in open(os.path.join(ROOT, "docs", "FILTER_FIELDS.md"), encoding="utf-8"):
        m = re.match(r"\| `([^`]+)` \|", line)
        if m:
            names.append(m.group(1))
    keywords = ["&&", "||", "!", "and", "or", "not", "==", "!=", "<=", ">=", "eq", "ne", "lt", "gt", "le", "ge", "contains",
                "matches", "in", "{", "}", "(", ")", "\"", "10.0.0.0/8", "192.168.0.1", "2001:db8::/32", "::1", "aa:bb:cc:dd:ee:ff",
                "0x", "true", "false", ".."]
    with open(os.path.join(FUZZ, "dict", "filter.dict"), "w") as f:
        f.write("# Display filter syntax and the field names of docs/FILTER_FIELDS.md: generated by tools/make_fuzz_seeds.py\n")
        for i, token in enumerate(keywords):
            f.write('kw%d="%s"\n' % (i, token.replace("\\", "\\\\").replace('"', '\\"')))
        for i, name in enumerate(names):
            f.write('field%d="%s"\n' % (i, name))


def main():
    table = read_link_table()
    os.makedirs(os.path.join(FUZZ, "dict"), exist_ok=True)
    capture_seeds()
    packet_seeds(table)
    filter_seeds()
    gzip_seeds()
    filter_dictionary()
    return 0


if __name__ == "__main__":
    sys.exit(main())

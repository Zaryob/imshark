#!/usr/bin/env python3
"""Compare ImShark's decoding of captures with Wireshark's tshark on a pinned set of fields.

Usage:
    python3 tools/compare_tshark.py [--config tools/compare_tshark.json] [--tshark PATH] [--imshark-dump PATH]
                                    [--tshark-json-dir DIR | --save-tshark-json DIR] [--report FILE] [--json FILE]
                                    CAPTURE_OR_DIRECTORY...

To compare the whole regression corpus on a machine that has tshark (build imshark_dump first; the default build does):
    cmake -S . -B build && cmake --build build --target imshark_dump
    python3 tools/compare_tshark.py --imshark-dump build/imshark_dump tests/corpus "$IMSHARK_CORPUS_DIR"

What is compared, per capture and per frame number:
  * packet loss:        a frame one side has and the other does not (the frame count and the frame numbers);
  * misclassification:  the protocol column (tshark's _ws.col.protocol against ImShark's protocol, after the aliases of
                        the config, case-insensitive);
  * field mismatches:   the fields listed in the config ("fields"): tshark -T json -e <field> against the same display
                        filter field of ImShark (tools/imshark_dump.cpp), after normalising addresses, numbers, MACs.
Captures named in "known_samples" of the config (known Unknown / encrypted / intentionally malformed files) get their own
section; their differences are listed but do not change the exit status.

tshark is run with the pinned preferences, Decode As entries and disabled heuristics of the config, in two-pass mode
(-2), and its version must start with "version_prefix" of the config. --save-tshark-json DIR keeps tshark's raw
output as DIR/<capture name>.json; --tshark-json-dir DIR compares against such recorded files instead of running
tshark (tests/data/tshark holds hand-written ones for the tests).

Exit codes: 0 no differences, 1 differences found, 2 usage or input error, 3 imshark_dump missing or failed,
4 tshark version differs from the pinned one, 77 tshark is not installed (the ctest skip code).
Stdlib only.
"""
import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, ".."))
CAPTURE_EXTENSIONS = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz", ".cap.gz")

EXIT_OK, EXIT_DIFF, EXIT_USAGE, EXIT_NO_DUMP, EXIT_VERSION, EXIT_NO_TSHARK = 0, 1, 2, 3, 4, 77


class Fatal(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- inputs

def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise Fatal(EXIT_USAGE, "cannot read config %s: %s" % (path, e))
    for key in ("tshark", "fields", "known_samples", "protocol_aliases"):
        if key not in cfg:
            raise Fatal(EXIT_USAGE, "config %s has no \"%s\"" % (path, key))
    for fld in cfg["fields"]:
        if fld.get("kind") not in ("uint", "string", "ip", "mac") or fld.get("mode") not in ("first", "if_present"):
            raise Fatal(EXIT_USAGE, "config field %s needs a kind (uint/string/ip/mac) and a mode (first/if_present)"
                        % fld.get("name"))
    return cfg


def collect_captures(paths):
    found = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                found.extend(os.path.join(root, f) for f in sorted(files) if f.lower().endswith(CAPTURE_EXTENSIONS))
        elif os.path.isfile(p):
            found.append(p)
        else:
            raise Fatal(EXIT_USAGE, "no such capture or directory: " + p)
    return found


def find_tshark(explicit):
    exe = explicit or shutil.which("tshark")
    if explicit and not os.path.isfile(explicit):
        exe = shutil.which(explicit)
    if not exe:
        raise Fatal(EXIT_NO_TSHARK, "tshark was not found (install Wireshark's command line tools or pass --tshark PATH); "
                                    "nothing was compared")
    return exe


def check_tshark_version(exe, cfg):
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise Fatal(EXIT_NO_TSHARK, "cannot run %s: %s" % (exe, e))
    first = out.splitlines()[0] if out else ""
    words = first.split()
    version = words[2] if len(words) >= 3 else ""
    pin = cfg["tshark"].get("version_prefix", "")
    if pin and not version.startswith(pin):
        raise Fatal(EXIT_VERSION, "tshark version is %r, the config pins %r*; the field names and dissectors may differ. "
                                  "Use a matching tshark or change version_prefix deliberately." % (version, pin))
    return first


def find_dump(explicit):
    # a path given on the command line is never replaced by a guess
    candidates = [explicit]
    if not explicit:
        candidates.append(os.environ.get("IMSHARK_DUMP"))
        for build in ("build", "build-v073", "build-release", "build-asan"):
            candidates.append(os.path.join(REPO_ROOT, build, "imshark_dump"))
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise Fatal(EXIT_NO_DUMP, "imshark_dump was not found (build it: cmake --build <build dir> --target imshark_dump, "
                              "then pass --imshark-dump PATH or set IMSHARK_DUMP)")


def tshark_command(exe, capture, cfg):
    t = cfg["tshark"]
    cmd = [exe, "-r", capture, "-T", "json"] + list(t.get("extra_args", []))
    for pref in t.get("preferences", []):
        cmd += ["-o", pref]
    for d in t.get("decode_as", []):
        cmd += ["-d", d]
    for proto in t.get("disable_heuristic", []):
        cmd += ["--disable-heuristic", proto]
    names = ["frame.number", t.get("protocol_column_field", "_ws.col.protocol")] + [f["tshark"] for f in cfg["fields"]]
    for n in names:
        cmd += ["-e", n]
    return cmd


def parse_tshark_json(text, cfg):
    """tshark -T json -e: [{"_source": {"layers": {field: [values]}}}, ...] -> {frame number: (protocol, {field: [str]})}"""
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError as e:
        raise Fatal(EXIT_USAGE, "tshark output is not JSON: %s" % e)
    column = cfg["tshark"].get("protocol_column_field", "_ws.col.protocol")
    frames = {}
    for item in data:
        layers = item.get("_source", {}).get("layers", {})
        values = {k: ([v] if isinstance(v, str) else [str(x) for x in v]) for k, v in layers.items()}
        try:
            number = int(values.get("frame.number", [""])[0])
        except ValueError:
            continue
        frames[number] = ((values.get(column) or [""])[0], values)
    return frames


def run_tshark(exe, capture, cfg, save_dir):
    proc = subprocess.run(tshark_command(exe, capture, cfg), capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise Fatal(EXIT_USAGE, "tshark failed on %s: %s" % (capture, proc.stderr.strip()[:300]))
    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        with open(os.path.join(save_dir, os.path.basename(capture) + ".json"), "w", encoding="utf-8") as f:
            f.write(proc.stdout)
    return proc.stdout


def run_dump(dump, capture, cfg):
    names = ",".join(["frame.number"] + [f["imshark"] for f in cfg["fields"]])
    proc = subprocess.run([dump, capture, "--fields", names], capture_output=True, text=True)
    if proc.returncode != 0:
        raise Fatal(EXIT_NO_DUMP, "imshark_dump failed on %s (exit %d): %s" % (capture, proc.returncode,
                                                                              proc.stderr.strip()[:300]))
    try:
        data = json.loads(proc.stdout)
    except ValueError as e:
        raise Fatal(EXIT_NO_DUMP, "imshark_dump output for %s is not JSON: %s" % (capture, e))
    return {p["number"]: (p["protocol"], p["fields"]) for p in data["packets"]}


# ---------------------------------------------------------------- comparison

def normalise(kind, value, ignore_case):
    try:
        if kind == "ip":
            return ipaddress.ip_address(value.strip()).compressed
        if kind == "mac":
            return value.strip().lower().replace("-", ":")
        if kind == "uint":
            v = value.strip()
            return str(int(v, 16) if v.lower().startswith("0x") else int(v, 10))
    except ValueError:
        return value
    return value.lower() if ignore_case else value


def protocol_key(name, aliases):
    return aliases.get(name, name).lower()


def compare_frames(tshark_frames, imshark_frames, cfg):
    """-> dict with lists: lost_in_imshark, extra_in_imshark, misclassified, mismatches (tuples with the frame number)."""
    aliases = cfg["protocol_aliases"]
    result = {"lost_in_imshark": [], "extra_in_imshark": [], "misclassified": [], "mismatches": []}
    for number in sorted(set(tshark_frames) | set(imshark_frames)):
        if number not in imshark_frames:
            result["lost_in_imshark"].append(number)
            continue
        if number not in tshark_frames:
            result["extra_in_imshark"].append(number)
            continue
        t_proto, t_fields = tshark_frames[number]
        i_proto, i_fields = imshark_frames[number]
        if protocol_key(t_proto, aliases) != protocol_key(i_proto, aliases):
            result["misclassified"].append((number, t_proto, i_proto))
        for fld in cfg["fields"]:
            ic = bool(fld.get("ignore_case"))
            t_vals = [normalise(fld["kind"], v, ic) for v in t_fields.get(fld["tshark"], [])]
            i_vals = [normalise(fld["kind"], v, ic) for v in i_fields.get(fld["imshark"], [])]
            if fld["mode"] == "if_present" and not i_vals:
                continue
            t_first = t_vals[0] if t_vals else None
            i_first = i_vals[0] if i_vals else None
            if t_first != i_first:
                result["mismatches"].append((number, fld["name"], t_first, i_first))
    return result


def differences(res):
    return sum(len(res[k]) for k in res)


# ---------------------------------------------------------------- report

def fmt_value(v):
    return "(none)" if v is None else repr(v)


def format_report(entries, versions):
    out = []
    add = out.append
    add("ImShark vs tshark comparison")
    for line in versions:
        add("  " + line)
    regular = [e for e in entries if not e["known"]]
    known = [e for e in entries if e["known"]]
    totals = {k: sum(len(e["result"][k]) for e in regular) for k in
              ("lost_in_imshark", "extra_in_imshark", "misclassified", "mismatches")}
    add("")
    add("== Summary ==")
    add("captures compared: %d (known samples: %d)" % (len(regular), len(known)))
    add("frames: tshark %d, ImShark %d" % (sum(e["tshark_frames"] for e in regular), sum(e["imshark_frames"] for e in regular)))
    add("packet loss: %d frame(s) missing in ImShark, %d only in ImShark" % (totals["lost_in_imshark"], totals["extra_in_imshark"]))
    add("misclassification: %d" % totals["misclassified"])
    add("field mismatches: %d" % totals["mismatches"])

    def section(title, rows):
        add("")
        add("== %s ==" % title)
        if not rows:
            add("none")
        out.extend(rows)

    def rows_for(group):
        rows = []
        for e in group:
            r = e["result"]
            for n in r["lost_in_imshark"]:
                rows.append("%s: frame %d is in tshark's output but not in ImShark's" % (e["name"], n))
            for n in r["extra_in_imshark"]:
                rows.append("%s: frame %d is in ImShark's output but not in tshark's" % (e["name"], n))
        return rows

    def class_rows(group):
        return ["%s: frame %d: tshark %r, ImShark %r" % (e["name"], n, t, i)
                for e in group for (n, t, i) in e["result"]["misclassified"]]

    def field_rows(group):
        return ["%s: frame %d: %s: tshark %s, ImShark %s" % (e["name"], n, f, fmt_value(t), fmt_value(i))
                for e in group for (n, f, t, i) in e["result"]["mismatches"]]

    section("Packet loss", rows_for(regular))
    section("Misclassification", class_rows(regular))
    section("Field mismatches", field_rows(regular))

    add("")
    add("== Known samples (reported separately, not counted) ==")
    if not known:
        add("none")
    for e in known:
        info = e["known"]
        add("%s [%s]: %s" % (e["name"], info.get("category", "?"), info.get("reason", "")))
        rows = rows_for([e]) + class_rows([e]) + field_rows([e])
        if not rows:
            add("  (no differences)")
        out.extend("  " + r for r in rows)
    add("")
    total = sum(totals.values())
    add("RESULT: " + ("no differences" if total == 0 else "%d difference(s)" % total))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+", metavar="CAPTURE_OR_DIRECTORY")
    ap.add_argument("--config", default=os.path.join(SCRIPT_DIR, "compare_tshark.json"))
    ap.add_argument("--tshark", default=None)
    ap.add_argument("--imshark-dump", default=None)
    ap.add_argument("--tshark-json-dir", default=None, help="compare against recorded DIR/<capture name>.json, do not run tshark")
    ap.add_argument("--save-tshark-json", default=None, metavar="DIR", help="keep tshark's raw output as DIR/<capture name>.json")
    ap.add_argument("--report", default=None, help="also write the text report to this file")
    ap.add_argument("--json", default=None, help="write the machine-readable result to this file")
    args = ap.parse_args(argv)
    if args.tshark_json_dir and args.save_tshark_json:
        ap.error("--tshark-json-dir and --save-tshark-json exclude each other")

    try:
        cfg = load_config(args.config)
        captures = collect_captures(args.captures)
        if not captures:
            raise Fatal(EXIT_USAGE, "no capture files found in the given paths")
        versions = []
        exe = None
        if args.tshark_json_dir:
            versions.append("tshark: recorded output from " + args.tshark_json_dir)
        else:
            exe = find_tshark(args.tshark)
            versions.append("tshark: " + check_tshark_version(exe, cfg))
        dump = find_dump(args.imshark_dump)
        versions.append("imshark_dump: " + dump)

        entries = []
        for cap in captures:
            name = os.path.basename(cap)
            if args.tshark_json_dir:
                rec = os.path.join(args.tshark_json_dir, name + ".json")
                try:
                    with open(rec, encoding="utf-8") as f:
                        text = f.read()
                except OSError:
                    raise Fatal(EXIT_USAGE, "no recorded tshark output for %s (expected %s)" % (name, rec))
            else:
                text = run_tshark(exe, cap, cfg, args.save_tshark_json)
            t_frames = parse_tshark_json(text, cfg)
            i_frames = run_dump(dump, cap, cfg)
            entries.append({"name": name, "known": cfg["known_samples"].get(name),
                            "tshark_frames": len(t_frames), "imshark_frames": len(i_frames),
                            "result": compare_frames(t_frames, i_frames, cfg)})
    except Fatal as e:
        print("compare_tshark: " + str(e), file=sys.stderr)
        return e.code

    report = format_report(entries, versions)
    sys.stdout.write(report)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"versions": versions, "captures": entries}, f, indent=1, default=list)
    return EXIT_DIFF if any(differences(e["result"]) for e in entries if not e["known"]) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

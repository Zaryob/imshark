#!/usr/bin/env python3
"""Tests of tools/compare_tshark.py. Stdlib unittest; run by ctest as `compare_tshark_fixtures`.

The comparator runs against hand-written tshark JSON (tests/data/tshark, written from the shape of
`tshark -T json -e ...` output) and the real imshark_dump on tests/corpus files. Set IMSHARK_DUMP to the imshark_dump
binary (ctest does). A fake tshark script (a Python file) covers the code path that runs the real program."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(ROOT, "tools", "compare_tshark.py")
CORPUS = os.path.join(ROOT, "tests", "corpus")
FIXTURES = os.path.join(HERE, "data", "tshark")
DUMP = os.environ.get("IMSHARK_DUMP", "")
CAPTURES = ["arp-little-endian.pcap", "ipv4-fragments.pcap", "ipv6-fragments-out-of-order.pcap",
            "ethernet-vlan-qinq.pcap", "linux-cooked-udp.pcap", "pcapng-undefined-interface.pcapng"]


def run(*args, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True, env=e)


def captures(names=CAPTURES):
    return [os.path.join(CORPUS, n) for n in names]


def section(report, title):
    """The lines of one '== title ==' section."""
    lines = report.splitlines()
    start = lines.index("== %s ==" % title) + 1
    end = start
    while end < len(lines) and not lines[end].startswith("== ") and not lines[end].startswith("RESULT"):
        end += 1
    return [l for l in lines[start:end] if l.strip()]


@unittest.skipUnless(DUMP and os.path.isfile(DUMP), "IMSHARK_DUMP does not name the imshark_dump binary")
class CompareTshark(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cmp_tshark_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def compare(self, fixtures=FIXTURES, names=CAPTURES, extra=()):
        return run("--imshark-dump", DUMP, "--tshark-json-dir", fixtures, *extra, *captures(names))

    def mutated(self, name, edit):
        """Copies the fixtures, applying edit(frames) to the recorded frames of `name`."""
        d = os.path.join(self.tmp, "fx")
        shutil.copytree(FIXTURES, d, dirs_exist_ok=True)
        path = os.path.join(d, name + ".json")
        with open(path, encoding="utf-8") as f:
            frames = json.load(f)
        edit(frames)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(frames, f)
        return d

    def test_recorded_fixtures_match_the_corpus(self):
        r = self.compare()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("captures compared: 5 (known samples: 1)", r.stdout)
        self.assertIn("frames: tshark 10, ImShark 10", r.stdout)
        self.assertIn("RESULT: no differences", r.stdout)
        for title in ("Packet loss", "Misclassification", "Field mismatches"):
            self.assertEqual(section(r.stdout, title), ["none"])

    def test_known_sample_differences_are_listed_apart_and_not_counted(self):
        r = self.compare()
        known = section(r.stdout, "Known samples (reported separately, not counted)")
        self.assertTrue(any("pcapng-undefined-interface.pcapng [unknown]" in l for l in known), known)
        self.assertTrue(any("frame 2: tshark 'ARP', ImShark 'Unknown'" in l for l in known), known)
        self.assertEqual(r.returncode, 0)

    def test_a_changed_field_is_a_mismatch(self):
        def edit(frames):
            frames[2]["_source"]["layers"]["udp.dstport"] = ["5353"]
        r = self.compare(self.mutated("ipv4-fragments.pcap", edit))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertEqual(section(r.stdout, "Field mismatches"),
                         ["ipv4-fragments.pcap: frame 3: udp.dstport: tshark '5353', ImShark '53'"])
        self.assertIn("RESULT: 1 difference(s)", r.stdout)

    def test_a_field_one_side_lacks_is_a_mismatch(self):
        def edit(frames):
            del frames[0]["_source"]["layers"]["ip.dst"]
        r = self.compare(self.mutated("ethernet-vlan-qinq.pcap", edit))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(section(r.stdout, "Field mismatches"),
                         ["ethernet-vlan-qinq.pcap: frame 1: ip.dst: tshark (none), ImShark '10.0.0.2'"])

    def test_a_changed_protocol_is_a_misclassification(self):
        def edit(frames):
            frames[2]["_source"]["layers"]["_ws.col.protocol"] = ["MDNS"]
        r = self.compare(self.mutated("ipv6-fragments-out-of-order.pcap", edit))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(section(r.stdout, "Misclassification"),
                         ["ipv6-fragments-out-of-order.pcap: frame 3: tshark 'MDNS', ImShark 'DNS'"])

    def test_missing_and_extra_frames_are_packet_loss(self):
        def drop(frames):
            frames.pop()                       # tshark has one frame fewer than ImShark
        r = self.compare(self.mutated("ipv4-fragments.pcap", drop))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(section(r.stdout, "Packet loss"),
                         ["ipv4-fragments.pcap: frame 3 is in ImShark's output but not in tshark's"])

        def add(frames):
            extra = json.loads(json.dumps(frames[0]))
            extra["_source"]["layers"]["frame.number"] = ["2"]
            frames.append(extra)               # tshark has a frame ImShark does not
        r = self.compare(self.mutated("ethernet-vlan-qinq.pcap", add))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(section(r.stdout, "Packet loss"),
                         ["ethernet-vlan-qinq.pcap: frame 2 is in tshark's output but not in ImShark's"])

    def test_normalisation_and_aliases(self):
        def edit(frames):
            layers = frames[0]["_source"]["layers"]
            layers["ipv6.src"] = ["2001:0db8:0000:0000:0000:0000:0000:0001"]   # same address, long form
            layers["_ws.col.protocol"] = ["ipv6"]                            # case differs
            layers["frame.len"] = ["0x43"]                                   # 67 in hex
        r = self.compare(self.mutated("ipv6-fragments-out-of-order.pcap", edit))
        self.assertEqual(r.returncode, 0, r.stdout)

        # TLSv1.2 (tshark's column) is ImShark's "TLS": the alias comes from the config
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        try:
            import compare_tshark as ct
        finally:
            sys.path.pop(0)
        cfg = ct.load_config(os.path.join(ROOT, "tools", "compare_tshark.json"))
        t = {1: ("TLSv1.3", {"frame.number": ["1"]})}
        i = {1: ("TLS", {})}
        self.assertEqual(ct.compare_frames(t, i, cfg)["misclassified"], [])
        self.assertEqual(ct.compare_frames({1: ("SSH", {})}, i, cfg)["misclassified"], [(1, "SSH", "TLS")])

    def test_json_and_report_files(self):
        out = os.path.join(self.tmp, "r.json")
        txt = os.path.join(self.tmp, "r.txt")
        r = self.compare(extra=("--json", out, "--report", txt))
        self.assertEqual(r.returncode, 0)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["captures"]), 6)
        with open(txt, encoding="utf-8") as f:
            self.assertEqual(f.read(), r.stdout)

    def test_missing_tshark_exits_77_with_a_message(self):
        r = run("--imshark-dump", DUMP, "--tshark", os.path.join(self.tmp, "no-such-tshark"), *captures(CAPTURES[:1]))
        self.assertEqual(r.returncode, 77)
        self.assertIn("tshark was not found", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_missing_imshark_dump_exits_3(self):
        r = run("--imshark-dump", os.path.join(self.tmp, "nope"), "--tshark-json-dir", FIXTURES, *captures(CAPTURES[:1]))
        self.assertEqual(r.returncode, 3)
        self.assertIn("imshark_dump was not found", r.stderr)

    def test_usage_errors_exit_2(self):
        self.assertEqual(run("--imshark-dump", DUMP, "--tshark-json-dir", FIXTURES, os.path.join(self.tmp, "x.pcap")).returncode, 2)
        r = run("--imshark-dump", DUMP, "--tshark-json-dir", self.tmp, *captures(CAPTURES[:1]))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no recorded tshark output", r.stderr)

    @unittest.skipIf(os.name == "nt", "the fake tshark is a script with a shebang")
    def test_runs_tshark_with_the_pinned_options_and_checks_its_version(self):
        log = os.path.join(self.tmp, "args.txt")
        fake = os.path.join(self.tmp, "tshark")
        with open(fake, "w", encoding="utf-8") as f:
            f.write("#!%s\n" % sys.executable)
            f.write("import os, sys\n"
                    "if sys.argv[1] == '--version':\n"
                    "    print('TShark (Wireshark) ' + os.environ.get('FAKE_VERSION', '4.2.5') + ' (fake)'); sys.exit(0)\n"
                    "open(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
                    "name = os.path.basename(sys.argv[2])\n"
                    "sys.stdout.write(open(os.path.join(%r, name + '.json')).read())\n" % (log, FIXTURES))
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        r = run("--imshark-dump", DUMP, "--tshark", fake, *captures(CAPTURES[:1]))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("tshark: TShark (Wireshark) 4.2.5 (fake)", r.stdout)
        with open(log, encoding="utf-8") as f:
            args = f.read().split()
        for needle in ("-T", "json", "-n", "-2", "ip.defragment:TRUE", "tcp.desegment_tcp_streams:TRUE",
                       "_ws.col.protocol", "dns.qry.name", "tls.handshake.extensions_server_name"):
            self.assertIn(needle, args)
        self.assertIn("-o", args)
        self.assertEqual(args[:2], ["-r", captures(CAPTURES[:1])[0]])

        r = run("--imshark-dump", DUMP, "--tshark", fake, *captures(CAPTURES[:1]), env={"FAKE_VERSION": "3.6.8"})
        self.assertEqual(r.returncode, 4)
        self.assertIn("pins '4.'", r.stderr)

    def test_imshark_dump_rejects_unknown_fields_and_writes_json(self):
        r = subprocess.run([DUMP, captures()[0], "--fields", "no.such.field"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([DUMP, captures()[3], "--fields", "ip.src,udp.port"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        pkt = json.loads(r.stdout)["packets"][0]
        self.assertEqual(pkt["protocol"], "UDP")
        self.assertEqual(pkt["fields"], {"ip.src": ["10.0.0.1"], "udp.port": ["1000", "2000"]})


if __name__ == "__main__":
    unittest.main()

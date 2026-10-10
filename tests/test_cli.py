#!/usr/bin/env python3
"""Pins the command-line contract documented in docs/COMPATIBILITY.md for `imshark` and `imshark_dump`.

Stdlib unittest; run by ctest as `cli_contract`. IMSHARK_DUMP and IMSHARK name the binaries (ctest sets them). Only
paths that return before a window is created are exercised for `imshark`, so this runs headless."""
import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "corpus", "ethernet-vlan-qinq.pcap")
DUMP = os.environ.get("IMSHARK_DUMP", "")
GUI = os.environ.get("IMSHARK", "")


def run(binary, *args):
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=60)


@unittest.skipUnless(DUMP and os.path.isfile(DUMP), "IMSHARK_DUMP does not name the imshark_dump binary")
class ImsharkDumpCli(unittest.TestCase):
    def test_no_arguments_and_unknown_flags_are_usage_errors_exit_2(self):
        for args in ([], ["--bogus"], [SAMPLE, "--bogus"], [SAMPLE, "extra.pcap"], [SAMPLE, "--fields"]):
            r = run(DUMP, *args)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("Usage: imshark_dump <capture file> [--fields name1,name2,...]", r.stderr)
            self.assertEqual(r.stdout, "")

    def test_unknown_field_is_exit_2_and_names_the_field(self):
        r = run(DUMP, SAMPLE, "--fields", "ip.src,no.such.field")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Unknown field: no.such.field", r.stderr)

    def test_unreadable_capture_is_exit_1(self):
        r = run(DUMP, os.path.join(tempfile.gettempdir(), "imshark-no-such-capture.pcap"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("Load failed:", r.stderr)

    def test_success_prints_the_documented_json_shape_exit_0(self):
        r = run(DUMP, SAMPLE, "--fields", "frame.number,ip.src")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(list(doc), ["packets"])
        self.assertTrue(doc["packets"])
        for p in doc["packets"]:
            self.assertEqual(list(p)[:3], ["number", "protocol", "fields"])
            self.assertLessEqual(set(p["fields"]), {"frame.number", "ip.src"})
            for values in p["fields"].values():
                self.assertIsInstance(values, list)
                self.assertTrue(all(isinstance(v, str) for v in values), "values are text")

    def test_default_field_set_is_accepted(self):
        r = run(DUMP, SAMPLE)
        self.assertEqual(r.returncode, 0, r.stderr)
        json.loads(r.stdout)


@unittest.skipUnless(GUI and os.path.isfile(GUI), "IMSHARK does not name the imshark binary")
class ImsharkCli(unittest.TestCase):
    def test_help_lists_exactly_the_documented_options(self):
        for flag in ("--help", "-h"):
            r = run(GUI, flag)
            self.assertEqual(r.returncode, 0)
            self.assertTrue(r.stdout.startswith("Usage: imshark [OPTIONS] [CAPTURE_FILE]"))
            for token in ("-h, --help", "-V, --version", "--  "):
                self.assertIn(token, r.stdout)

    def test_version_prints_name_version_and_describe_exit_0(self):
        for flag in ("--version", "-V"):
            r = run(GUI, flag)
            self.assertEqual(r.returncode, 0)
            self.assertRegex(r.stdout, r"^imshark \d+\.\d+\.\d+\S* \(.+\)\n$")

    def test_invalid_arguments_exit_1_with_usage_on_stderr(self):
        for args in (["--bogus"], ["a.pcap", "b.pcap"], ["--help", "x"], ["-V", "x"], ["--"], ["--", "a", "b"]):
            r = run(GUI, *args)
            self.assertEqual(r.returncode, 1, args)
            self.assertIn("Invalid arguments.", r.stderr)
            self.assertIn("Usage: imshark", r.stderr)


if __name__ == "__main__":
    unittest.main()

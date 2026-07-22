#!/usr/bin/env python3
"""Unit tests for parser.py.

Run from the project root with:

    python -m unittest discover -s tests

or simply:

    python tests/test_parser.py
"""
import io
import os
import sys
import unittest
import xml.etree.ElementTree as ET

# Make the parser module importable regardless of where tests are run from.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import parser  # noqa: E402

SAMPLES = os.path.join(PROJECT_ROOT, "samples")


def sample(name):
    return os.path.join(SAMPLES, name)


class ParseEventID1Tests(unittest.TestCase):
    def test_single_event_fields(self):
        events = parser.parse_file(sample("event1.xml"))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["EventID"], "1")
        self.assertEqual(event["EventType"], "Process Create")
        self.assertEqual(event["Image"], r"C:\Windows\System32\whoami.exe")
        self.assertEqual(event["CommandLine"], "whoami /all")
        self.assertEqual(event["IntegrityLevel"], "Medium")
        self.assertIn("SHA256=", event["Hashes"])
        self.assertEqual(event["Computer"], "WORKSTATION-07.corp.example.com")

    def test_all_claude_md_fields_present(self):
        event = parser.parse_file(sample("event1.xml"))[0]
        for field in [
            "EventID", "UtcTime", "Image", "CommandLine", "User",
            "IntegrityLevel", "ParentImage", "ParentCommandLine",
            "Computer", "Hashes",
        ]:
            self.assertIn(field, event)


class MultiEventTests(unittest.TestCase):
    def test_events_wrapper_returns_list(self):
        events = parser.parse_file(sample("multi_events.xml"))
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e["EventID"] == "1" for e in events))

    def test_mixed_event_ids(self):
        events = parser.parse_file(sample("mixed_events.xml"))
        ids = [e["EventID"] for e in events]
        self.assertEqual(ids, ["1", "3", "10", "22"])

    def test_network_event_fields(self):
        events = parser.parse_file(sample("mixed_events.xml"))
        net = next(e for e in events if e["EventID"] == "3")
        self.assertEqual(net["EventType"], "Network Connection")
        self.assertEqual(net["DestinationIp"], "203.0.113.44")
        self.assertEqual(net["DestinationPort"], "8443")
        # Event ID 1-only fields must NOT be forced onto a network event.
        self.assertNotIn("CommandLine", net)


class FallbackTests(unittest.TestCase):
    def test_unmapped_event_emits_all_fields(self):
        events = parser.parse_file(sample("mixed_events.xml"))
        access = next(e for e in events if e["EventID"] == "10")
        # No curated schema for ID 10 -> every Data field should survive.
        self.assertEqual(access["TargetImage"], r"C:\Windows\System32\lsass.exe")
        self.assertEqual(access["GrantedAccess"], "0x1410")
        self.assertIn("CallTrace", access)


class NamespaceTests(unittest.TestCase):
    def test_parses_without_namespace(self):
        xml = (
            "<Event>"
            "<System><EventID>1</EventID>"
            "<Computer>HOST-A</Computer></System>"
            "<EventData>"
            '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
            '<Data Name="CommandLine">cmd.exe /c echo hi</Data>'
            "</EventData></Event>"
        )
        root = ET.fromstring(xml)
        event = parser.parse_event(root)
        self.assertEqual(event["EventID"], "1")
        self.assertEqual(event["Image"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(event["Computer"], "HOST-A")


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.events = parser.parse_file(sample("mixed_events.xml"))

    def test_image_substring_match(self):
        result = parser.filter_events(self.events, image="powershell")
        # IDs 1, 3, 22 have a powershell Image; ID 10 has no Image field.
        self.assertEqual([e["EventID"] for e in result], ["1", "3", "22"])

    def test_image_is_case_insensitive(self):
        result = parser.filter_events(self.events, image="POWERSHELL")
        self.assertEqual(len(result), 3)

    def test_user_exact_match(self):
        result = parser.filter_events(self.events, user="corp\\jsmith")
        # ID 10 uses SourceUser/TargetUser, not User -> excluded.
        self.assertEqual([e["EventID"] for e in result], ["1", "3", "22"])

    def test_user_does_not_substring_match(self):
        result = parser.filter_events(self.events, user="jsmith")
        self.assertEqual(result, [])

    def test_integrity_match_excludes_missing_field(self):
        result = parser.filter_events(self.events, integrity="high")
        # Only the Process Create event carries IntegrityLevel = High.
        self.assertEqual([e["EventID"] for e in result], ["1"])

    def test_multiple_filters_are_anded(self):
        result = parser.filter_events(
            self.events, image="powershell", integrity="High"
        )
        self.assertEqual([e["EventID"] for e in result], ["1"])

    def test_no_filters_returns_all(self):
        result = parser.filter_events(self.events)
        self.assertEqual(len(result), len(self.events))

    def test_main_filter_zero_match_exits_zero(self):
        saved = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = parser.main(
                ["parser.py", sample("event1.xml"), "--user", "CORP\\nobody"]
            )
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "[]")


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.events = parser.parse_file(sample("multi_events.xml"))

    def test_json_multiple_is_array(self):
        import json as _json
        text = parser.format_events(self.events, "json")
        parsed = _json.loads(text)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 3)

    def test_json_single_is_object(self):
        import json as _json
        text = parser.format_events(self.events[:1], "json")
        parsed = _json.loads(text)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["EventID"], "1")

    def test_jsonl_one_object_per_line(self):
        import json as _json
        text = parser.format_events(self.events, "jsonl")
        lines = text.splitlines()
        self.assertEqual(len(lines), 3)
        # Every line must be a standalone JSON object.
        for line in lines:
            self.assertIsInstance(_json.loads(line), dict)

    def test_csv_header_and_rows_roundtrip(self):
        import csv as _csv
        import io as _io
        text = parser.format_events(self.events, "csv")
        rows = list(_csv.DictReader(_io.StringIO(text)))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["EventID"], "1")
        self.assertEqual(rows[0]["CommandLine"], 'net group "Domain Admins" /domain')

    def test_csv_columns_are_union_for_mixed_events(self):
        import csv as _csv
        import io as _io
        mixed = parser.parse_file(sample("mixed_events.xml"))
        text = parser.format_events(mixed, "csv")
        header = next(_csv.reader(_io.StringIO(text)))
        # Fields unique to the fallback (ID 10) event must appear as columns.
        self.assertIn("TargetImage", header)
        self.assertIn("GrantedAccess", header)

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            parser.format_events(self.events, "xml")

    def test_main_jsonl_via_cli(self):
        saved = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = parser.main(
                ["parser.py", sample("multi_events.xml"), "--format", "jsonl"]
            )
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(rc, 0)
        self.assertEqual(len([l for l in out.splitlines() if l]), 3)


class ErrorHandlingTests(unittest.TestCase):
    def test_no_events_returns_empty_list(self):
        root = ET.fromstring("<root><foo>bar</foo></root>")
        # parse_event is per-event; parse_file drives discovery. Emulate a
        # non-Sysmon document via a temporary tree.
        events = [
            parser.parse_event(e)
            for e in parser._iter_local(root, "Event")
        ]
        self.assertEqual(events, [])

    def test_main_errors_on_missing_file(self):
        rc = parser.main(["parser.py", sample("does_not_exist.xml")])
        self.assertEqual(rc, 1)

    def test_main_success(self):
        # Capture stdout to keep test output clean while checking the rc.
        saved = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = parser.main(["parser.py", sample("event1.xml")])
        finally:
            sys.stdout = saved
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

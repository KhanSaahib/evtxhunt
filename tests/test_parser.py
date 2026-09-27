import unittest
from pathlib import Path

from evtxhunt.parser import load_events, parse_jsonl_events, parse_xml_events

FIXTURES = Path(__file__).parent / "fixtures"


class ParseXmlEventsTest(unittest.TestCase):
    def test_parses_all_event_fragments(self):
        events = parse_xml_events((FIXTURES / "sample_events.xml").read_text())
        self.assertEqual(len(events), 4)

    def test_normalizes_system_and_eventdata_fields(self):
        events = parse_xml_events((FIXTURES / "sample_events.xml").read_text())
        first = events[0]
        self.assertEqual(first["EventID"], 4688)
        self.assertEqual(first["Channel"], "Security")
        self.assertEqual(first["Computer"], "WORKSTATION01.corp.local")
        self.assertEqual(first["TimeCreated"], "2026-01-01T10:00:00.000000Z")
        self.assertEqual(first["EventData"]["NewProcessName"], "C:\\Windows\\System32\\rundll32.exe")

    def test_handles_missing_eventdata(self):
        events = parse_xml_events((FIXTURES / "sample_events.xml").read_text())
        cleared = [e for e in events if e["EventID"] == 1102][0]
        self.assertEqual(cleared["EventData"], {})

    def test_empty_input_returns_no_events(self):
        self.assertEqual(parse_xml_events("   "), [])

    def test_malformed_xml_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_xml_events("<Event><System></Event>")


class ParseJsonlEventsTest(unittest.TestCase):
    def test_parses_each_line(self):
        events = parse_jsonl_events((FIXTURES / "sample_events.jsonl").read_text())
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["EventID"], 4104)
        self.assertIn("ScriptBlockText", events[0]["EventData"])

    def test_skips_blank_lines(self):
        events = parse_jsonl_events("\n{\"EventID\": 1}\n\n")
        self.assertEqual(len(events), 1)

    def test_invalid_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_jsonl_events("{not valid json}")


class LoadEventsTest(unittest.TestCase):
    def test_dispatches_by_content_xml(self):
        events = load_events(FIXTURES / "sample_events.xml")
        self.assertEqual(len(events), 4)

    def test_dispatches_by_content_jsonl(self):
        events = load_events(FIXTURES / "sample_events.jsonl")
        self.assertEqual(len(events), 2)


if __name__ == "__main__":
    unittest.main()

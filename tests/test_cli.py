import json
import unittest
from pathlib import Path

from evtxhunt.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class CliScanTest(unittest.TestCase):
    def test_scan_xml_fixture_json_output(self, capsys=None):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["scan", str(FIXTURES / "sample_events.xml"), "--format", "json"])
        self.assertEqual(rc, 0)
        incidents = json.loads(buf.getvalue())
        hosts = {inc["host"] for inc in incidents}
        self.assertIn("WORKSTATION01.corp.local", hosts)
        workstation = next(i for i in incidents if i["host"] == "WORKSTATION01.corp.local")
        self.assertGreaterEqual(len(workstation["distinct_rules"]), 2)

    def test_scan_jsonl_fixture_text_output(self):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["scan", str(FIXTURES / "sample_events.jsonl"), "--format", "text"])
        self.assertEqual(rc, 0)
        self.assertIn("JSONHOST.corp.local", buf.getvalue())

    def test_min_score_filters_low_scoring_incidents(self):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([
                "scan",
                str(FIXTURES / "sample_events.xml"),
                "--format",
                "json",
                "--min-score",
                "999",
            ])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue()), [])


if __name__ == "__main__":
    unittest.main()

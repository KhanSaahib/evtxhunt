import unittest

from evtxhunt.rules import Rule, RuleError, load_rules, scan_events


def make_event(**overrides):
    event = {
        "EventID": 4688,
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "HOST01",
        "TimeCreated": "2026-01-01T00:00:00Z",
        "RecordID": 1,
        "EventData": {},
    }
    event.update(overrides)
    return event


class RuleMatchingTest(unittest.TestCase):
    def test_simple_equality_and_channel_filter(self):
        rule = Rule({
            "title": "t",
            "level": "high",
            "logsource": {"channel": "Security"},
            "detection": {"selection": {"EventID": 4688}, "condition": "selection"},
        })
        self.assertTrue(rule.evaluate(make_event()))
        self.assertFalse(rule.evaluate(make_event(Channel="System")))
        self.assertFalse(rule.evaluate(make_event(EventID=4625)))

    def test_contains_modifier_is_case_insensitive(self):
        rule = Rule({
            "title": "t",
            "detection": {
                "selection": {"EventData.CommandLine|contains": "ENCODEDCOMMAND"},
                "condition": "selection",
            },
        })
        event = make_event(EventData={"CommandLine": "powershell -EncodedCommand abcd"})
        self.assertTrue(rule.evaluate(event))

    def test_list_values_are_ored(self):
        rule = Rule({
            "title": "t",
            "detection": {"selection": {"EventID": [4720, 4732]}, "condition": "selection"},
        })
        self.assertTrue(rule.evaluate(make_event(EventID=4732)))
        self.assertFalse(rule.evaluate(make_event(EventID=4625)))

    def test_and_not_condition(self):
        rule = Rule({
            "title": "t",
            "detection": {
                "selection": {"EventID": 4688},
                "filter": {"EventData.NewProcessName|contains": "notepad.exe"},
                "condition": "selection and not filter",
            },
        })
        self.assertTrue(rule.evaluate(make_event(EventData={"NewProcessName": "cmd.exe"})))
        self.assertFalse(rule.evaluate(make_event(EventData={"NewProcessName": "notepad.exe"})))

    def test_multi_selection_or_condition(self):
        rule = Rule({
            "title": "t",
            "logsource": {},
            "detection": {
                "a": {"EventID": 1102},
                "b": {"EventID": 104},
                "condition": "a or b",
            },
        })
        self.assertTrue(rule.evaluate(make_event(EventID=1102)))
        self.assertTrue(rule.evaluate(make_event(EventID=104)))
        self.assertFalse(rule.evaluate(make_event(EventID=1)))

    def test_1_of_quantifier(self):
        rule = Rule({
            "title": "t",
            "detection": {
                "selection_a": {"EventID": 1},
                "selection_b": {"EventID": 2},
                "condition": "1 of selection*",
            },
        })
        self.assertTrue(rule.evaluate(make_event(EventID=2)))
        self.assertFalse(rule.evaluate(make_event(EventID=3)))

    def test_rule_missing_condition_raises(self):
        with self.assertRaises(RuleError):
            Rule({"title": "t", "detection": {"selection": {"EventID": 1}}})

    def test_condition_referencing_unknown_selection_raises(self):
        rule = Rule({
            "title": "t",
            "detection": {"selection": {"EventID": 1}, "condition": "selection and bogus"},
        })
        with self.assertRaises(RuleError):
            rule.evaluate(make_event(EventID=1))


class LoadAndScanTest(unittest.TestCase):
    def test_bundled_rule_pack_loads_without_errors(self):
        from pathlib import Path

        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        rules = load_rules(rules_dir)
        self.assertGreaterEqual(len(rules), 10)

    def test_scan_events_returns_hits_for_matching_events(self):
        rule = Rule({
            "title": "t",
            "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
        })
        events = [make_event(EventID=4625), make_event(EventID=4688)]
        hits = scan_events(events, [rule])
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0]["rule"], rule)


if __name__ == "__main__":
    unittest.main()

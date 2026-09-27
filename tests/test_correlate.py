import unittest

from evtxhunt.correlate import correlate
from evtxhunt.rules import Rule


def make_rule(rule_id, level="medium", tags=None):
    return Rule({
        "id": rule_id,
        "title": rule_id,
        "level": level,
        "tags": tags or [],
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
    })


def make_hit(rule, host, time_created):
    return {"rule": rule, "event": {"Computer": host, "TimeCreated": time_created}}


class CorrelateTest(unittest.TestCase):
    def test_groups_hits_within_window_by_host(self):
        rule = make_rule("r1", level="low")
        hits = [
            make_hit(rule, "HOST1", "2026-01-01T00:00:00+00:00"),
            make_hit(rule, "HOST1", "2026-01-01T00:05:00+00:00"),
        ]
        incidents = correlate(hits, window_minutes=15)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["hit_count"], 2)

    def test_splits_groups_outside_window(self):
        rule = make_rule("r1", level="low")
        hits = [
            make_hit(rule, "HOST1", "2026-01-01T00:00:00+00:00"),
            make_hit(rule, "HOST1", "2026-01-01T01:00:00+00:00"),
        ]
        incidents = correlate(hits, window_minutes=15)
        self.assertEqual(len(incidents), 2)

    def test_distinct_rules_score_higher_than_repeats_of_one_rule(self):
        rule_a = make_rule("r1", level="low")
        rule_b = make_rule("r2", level="low")
        repeated_hits = [make_hit(rule_a, "HOST1", "2026-01-01T00:00:00+00:00")] * 2
        chained_hits = [
            make_hit(rule_a, "HOST2", "2026-01-01T00:00:00+00:00"),
            make_hit(rule_b, "HOST2", "2026-01-01T00:01:00+00:00"),
        ]
        incidents = correlate(repeated_hits + chained_hits, window_minutes=15)
        by_host = {i["host"]: i for i in incidents}
        self.assertGreater(by_host["HOST2"]["score"], by_host["HOST1"]["score"])

    def test_incidents_sorted_by_score_descending(self):
        rule_high = make_rule("r1", level="critical")
        rule_low = make_rule("r2", level="low")
        hits = [
            make_hit(rule_low, "QUIET_HOST", "2026-01-01T00:00:00+00:00"),
            make_hit(rule_high, "LOUD_HOST", "2026-01-01T00:00:00+00:00"),
        ]
        incidents = correlate(hits, window_minutes=15)
        self.assertEqual(incidents[0]["host"], "LOUD_HOST")

    def test_missing_timestamp_still_groups_with_first_seen(self):
        rule = make_rule("r1")
        hits = [make_hit(rule, "HOST1", None), make_hit(rule, "HOST1", None)]
        incidents = correlate(hits, window_minutes=15)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["hit_count"], 2)


if __name__ == "__main__":
    unittest.main()

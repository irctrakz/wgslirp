"""Checks of the acceptance oracle, independent of Go test execution."""

import json
from types import SimpleNamespace
import unittest

from failure_checks import verify_test


class AcceptanceOracleTests(unittest.TestCase):
    def verify(self, events, expected="fail", diagnostic="intended defect"):
        log = SimpleNamespace(read_text=lambda **_: "\n".join(json.dumps(e) for e in events))
        verify_test(log, "Required", expected, diagnostic)

    def events(self, action="fail", output="intended defect", test="Required"):
        return [{"Action": "output", "Test": test, "Output": output},
                {"Action": action, "Test": test}, {"Action": action}]

    def test_expected_assertion_is_accepted(self):
        self.verify(self.events())

    def test_baseline_must_pass(self):
        self.verify(self.events("pass"), "pass", None)

    def test_surviving_mutant_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(self.events("pass"))

    def test_skip_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(self.events("skip"))

    def test_missing_test_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify([])

    def test_compile_failure_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify([{"Action": "fail"}])

    def test_wrong_assertion_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(self.events(output="unrelated failure"))

    def test_other_test_cannot_supply_diagnostic(self):
        events = self.events(output="unrelated failure")
        events.append({"Action": "output", "Test": "Other", "Output": "intended defect"})
        with self.assertRaises(RuntimeError):
            self.verify(events)

    def test_panics_and_races_are_rejected(self):
        for text in ("panic: intended defect", "WARNING: DATA RACE intended defect"):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                self.verify(self.events(output=text))

    def test_child_assertion_is_accepted(self):
        events = self.events(output="")
        events.insert(0, {"Action": "output", "Test": "Required/child", "Output": "intended defect"})
        events.insert(1, {"Action": "fail", "Test": "Required/child"})
        self.verify(events)

    def test_partial_skip_is_rejected(self):
        events = self.events()
        events.insert(0, {"Action": "skip", "Test": "Required/child"})
        with self.assertRaises(RuntimeError):
            self.verify(events)


if __name__ == "__main__":
    unittest.main()

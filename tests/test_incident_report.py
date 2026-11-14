"""Tests for Markdown incident reports."""
import tempfile
import unittest
from pathlib import Path

from src.incident_report import generate_incident_report


def sample():
    return {"source_ip": "203.0.113.1", "severity": "HIGH", "attack_start_timestamp": "2026-01-01T00:00:00", "attack_end_timestamp": "2026-01-01T00:00:10", "total_failed_attempts": 10, "targeted_usernames": ["admin"], "threshold": 10, "time_window_seconds": 60}


class IncidentReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_one_incident(self):
        text = generate_incident_report([sample()], output_path=self.root / "r.md")
        self.assertIn("Incident 1", text)

    def test_multiple_incidents(self):
        text = generate_incident_report([sample(), sample()], output_path=self.root / "r")
        self.assertEqual(text.count("### Incident"), 2)

    def test_empty_incidents(self):
        text = generate_incident_report([], output_path=self.root / "r")
        self.assertIn("No incidents were detected", text)
        self.assertIn("No detector evidence is available for triage", text)

    def test_severity_distribution(self):
        text = generate_incident_report([sample()], output_path=self.root / "r")
        self.assertIn("HIGH: 1", text)

    def test_source_ip(self):
        self.assertIn("203.0.113.1", generate_incident_report([sample()], output_path=self.root / "r"))

    def test_timestamps(self):
        text = generate_incident_report([sample()], output_path=self.root / "r")
        self.assertIn("2026-01-01T00:00:00", text)
        self.assertIn("2026-01-01T00:00:10", text)

    def test_attempt_count(self):
        self.assertIn("Failed attempts: 10", generate_incident_report([sample()], output_path=self.root / "r"))

    def test_usernames(self):
        self.assertIn("admin", generate_incident_report([sample()], output_path=self.root / "r"))

    def test_alert_association(self):
        alert = {"alert_id": "abc", "source_ip": "203.0.113.1", "attack_start_timestamp": sample()["attack_start_timestamp"], "attack_end_timestamp": sample()["attack_end_timestamp"]}
        self.assertIn("Alert ID: abc", generate_incident_report([sample()], [alert], self.root / "r"))

    def test_triage_uses_detector_evidence_and_alert_id(self):
        alert = {"alert_id": "abc", "source_ip": "203.0.113.1", "attack_start_timestamp": sample()["attack_start_timestamp"], "attack_end_timestamp": sample()["attack_end_timestamp"]}
        text = generate_incident_report([sample()], [alert], self.root / "r")
        self.assertIn("Incident-Response Triage Summary", text)
        self.assertIn("Detected source IP: `203.0.113.1`", text)
        self.assertIn("Failed attempt count: 10", text)
        self.assertIn("Related alert ID: abc", text)
        self.assertIn("does not by itself prove malicious activity", text)

    def test_optional_alerts(self):
        self.assertIn("Incident 1", generate_incident_report([sample()], output_path=self.root / "r"))

    def test_safe_recommendations(self):
        text = generate_incident_report([sample()], output_path=self.root / "r")
        self.assertIn("Review authentication logs", text)
        self.assertIn("not automated actions", text)

    def test_custom_path(self):
        path = self.root / "custom.md"
        generate_incident_report([], output_path=path)
        self.assertTrue(path.is_file())

    def test_parent_created(self):
        path = self.root / "nested" / "r.md"
        generate_incident_report([], output_path=path)
        self.assertTrue(path.is_file())

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            generate_incident_report("bad", output_path=self.root / "r")

    def test_write_error(self):
        blocker = self.root / "file"
        blocker.write_text("x")
        with self.assertRaises(OSError):
            generate_incident_report([], output_path=blocker / "r.md")


if __name__ == "__main__":
    unittest.main()

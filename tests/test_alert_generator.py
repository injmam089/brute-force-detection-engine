"""Tests for structured JSON alert generation."""

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

from src.alert_generator import generate_alerts


def incident(**updates: Any) -> Dict[str, Any]:
    """Return a synthetic detector incident for isolated tests."""
    value = {
        "source_ip": "203.0.113.10",
        "attack_start_timestamp": "2026-11-13T10:00:00",
        "attack_end_timestamp": "2026-11-13T10:00:45",
        "total_failed_attempts": 10,
        "targeted_usernames": ["admin", "ops_team"],
        "threshold": 10,
        "time_window_seconds": 60,
        "severity": "HIGH",
    }
    value.update(updates)
    return value


class AlertGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def test_one_incident_produces_one_alert(self) -> None:
        result = generate_alerts([incident()], self.root / "alerts.json")
        self.assertEqual(result["total_alerts"], 1)
        self.assertEqual(len(result["alerts"]), 1)

    def test_multiple_incidents_produce_multiple_alerts(self) -> None:
        result = generate_alerts(
            [incident(), incident(source_ip="198.51.100.4")],
            self.root / "alerts.json",
        )
        self.assertEqual(result["total_alerts"], 2)

    def test_empty_incidents_produce_no_fabricated_alerts(self) -> None:
        result = generate_alerts([], self.root / "empty.json")
        self.assertEqual(result["total_alerts"], 0)
        self.assertEqual(result["alerts"], [])

    def test_required_alert_fields_exist(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        required = {
            "alert_id", "alert_type", "severity", "status", "source_ip",
            "attack_start_timestamp", "attack_end_timestamp",
            "total_failed_attempts", "targeted_usernames", "threshold",
            "time_window_seconds", "detected_at",
        }
        self.assertTrue(required.issubset(alert))

    def test_alert_type_is_correct(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["alert_type"], "BRUTE_FORCE_DETECTED")

    def test_severity_is_preserved(self) -> None:
        alert = generate_alerts(
            [incident(severity="MEDIUM")], self.root / "alerts.json"
        )["alerts"][0]
        self.assertEqual(alert["severity"], "MEDIUM")

    def test_status_defaults_to_open(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["status"], "OPEN")

    def test_source_ip_is_preserved(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["source_ip"], "203.0.113.10")

    def test_attack_timestamps_are_preserved(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["attack_start_timestamp"], "2026-11-13T10:00:00")
        self.assertEqual(alert["attack_end_timestamp"], "2026-11-13T10:00:45")

    def test_attempt_count_is_preserved(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["total_failed_attempts"], 10)

    def test_targeted_usernames_are_preserved(self) -> None:
        names = ["admin", "ops_team"]
        alert = generate_alerts(
            [incident(targeted_usernames=names)], self.root / "alerts.json"
        )["alerts"][0]
        self.assertEqual(alert["targeted_usernames"], names)

    def test_threshold_and_window_are_preserved(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        self.assertEqual(alert["threshold"], 10)
        self.assertEqual(alert["time_window_seconds"], 60)

    def test_detected_at_is_utc_aware(self) -> None:
        alert = generate_alerts([incident()], self.root / "alerts.json")["alerts"][0]
        detected_at = datetime.fromisoformat(alert["detected_at"])
        self.assertIsNotNone(detected_at.tzinfo)
        self.assertEqual(detected_at.utcoffset().total_seconds(), 0)

    def test_output_is_valid_readable_json(self) -> None:
        output_path = self.root / "alerts.json"
        result = generate_alerts([incident()], output_path)
        loaded = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded, result)
        self.assertIn("\n  \"alerts\"", output_path.read_text(encoding="utf-8"))

    def test_missing_output_directory_is_created(self) -> None:
        output_path = self.root / "new" / "nested" / "alerts.json"
        generate_alerts([incident()], output_path)
        self.assertTrue(output_path.is_file())

    def test_invalid_incident_input_raises_clear_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "incidents must be a list"):
            generate_alerts("bad", self.root / "alerts.json")
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            generate_alerts([{"source_ip": "203.0.113.10"}], self.root / "x.json")

    def test_distinct_alerts_have_distinct_ids(self) -> None:
        alerts = generate_alerts(
            [incident(), incident(source_ip="198.51.100.4")],
            self.root / "alerts.json",
        )["alerts"]
        self.assertNotEqual(alerts[0]["alert_id"], alerts[1]["alert_id"])
        self.assertRegex(alerts[0]["alert_id"], r"^[0-9a-f-]{36}$")

    def test_custom_output_path_is_respected(self) -> None:
        output_path = self.root / "custom" / "chosen.json"
        generate_alerts([], output_path)
        self.assertTrue(output_path.is_file())
        self.assertFalse((self.root / "alerts.json").exists())

    def test_file_writing_errors_are_reported(self) -> None:
        blocker = self.root / "file-not-directory"
        blocker.write_text("occupied", encoding="utf-8")
        with self.assertRaisesRegex(OSError, "Unable to write alerts"):
            generate_alerts([incident()], blocker / "alerts.json")

    def test_default_output_uses_configured_directory(self) -> None:
        config_path = self.root / "config" / "detection_config.json"
        config_path.parent.mkdir(parents=True)
        with patch("src.alert_generator._CONFIG_PATH", config_path):
            config_path.write_text(
                json.dumps({"output_directory": "chosen-output"}),
                encoding="utf-8",
            )
            generate_alerts([])
        self.assertTrue(
            (self.root / "chosen-output" / "security_alert.json").is_file()
        )


if __name__ == "__main__":
    unittest.main()

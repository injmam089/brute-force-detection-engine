"""Unit tests for the sliding-window SSH brute-force detector."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from src.detector import (
    detect_brute_force,
    group_failed_events,
    load_detection_config,
)
from src.log_parser import parse_auth_log


class DetectorTests(unittest.TestCase):
    """Verify event filtering, sliding windows, and episode merging."""

    _BASE_TIME = datetime(2026, 11, 13, 10, 0, 0)

    @classmethod
    def _event(
        cls,
        seconds: int,
        source_ip: str = "203.0.113.10",
        event_type: str = "FAILED_LOGIN",
        username: Optional[str] = "admin",
    ) -> Dict[str, Any]:
        timestamp = cls._BASE_TIME + timedelta(seconds=seconds)
        return {
            "timestamp": timestamp.isoformat(timespec="seconds"),
            "hostname": "server01",
            "service": "sshd",
            "pid": 1234,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "raw_line": "synthetic test event",
            "line_number": seconds + 1,
        }

    @staticmethod
    def _config(
        threshold: int = 10,
        window: int = 60,
        severity: str = "HIGH",
    ) -> Dict[str, Any]:
        return {
            "failed_attempt_threshold": threshold,
            "time_window_seconds": window,
            "severity": severity,
        }

    def test_exactly_ten_attempts_within_sixty_seconds(self) -> None:
        events = [self._event(seconds) for seconds in range(0, 60, 6)]

        incidents = detect_brute_force(events, self._config())

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["total_failed_attempts"], 10)
        self.assertEqual(incidents[0]["threshold"], 10)
        self.assertEqual(incidents[0]["time_window_seconds"], 60)

    def test_nine_attempts_within_sixty_seconds_do_not_trigger(self) -> None:
        events = [self._event(seconds) for seconds in range(0, 54, 6)]

        self.assertEqual(detect_brute_force(events, self._config()), [])

    def test_ten_attempts_spread_outside_window_do_not_trigger(self) -> None:
        events = [self._event(index * 61) for index in range(10)]

        self.assertEqual(detect_brute_force(events, self._config()), [])

    def test_source_ip_addresses_are_correlated_independently(self) -> None:
        mixed_events = [
            self._event(index, source_ip="203.0.113.10")
            for index in range(9)
        ] + [self._event(9, source_ip="198.51.100.20")]
        self.assertEqual(detect_brute_force(mixed_events, self._config()), [])

        two_attacks = [
            self._event(index, source_ip="203.0.113.10")
            for index in range(10)
        ] + [
            self._event(index, source_ip="198.51.100.20")
            for index in range(10)
        ]
        incidents = detect_brute_force(two_attacks, self._config())

        self.assertEqual(
            [incident["source_ip"] for incident in incidents],
            ["198.51.100.20", "203.0.113.10"],
        )

    def test_successful_logins_are_excluded(self) -> None:
        events = [self._event(index) for index in range(9)]
        events.append(
            self._event(9, event_type="SUCCESSFUL_LOGIN", username="admin")
        )

        self.assertEqual(detect_brute_force(events, self._config()), [])

    def test_invalid_source_addresses_are_excluded(self) -> None:
        events = [
            self._event(index, source_ip="999.0.0.1") for index in range(10)
        ]

        self.assertEqual(group_failed_events(events), {})
        self.assertEqual(detect_brute_force(events, self._config()), [])

    def test_duplicate_timestamps_count_as_separate_attempts(self) -> None:
        events = [self._event(0) for _ in range(10)]

        incidents = detect_brute_force(events, self._config())

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["total_failed_attempts"], 10)
        self.assertEqual(
            incidents[0]["attack_start_timestamp"],
            incidents[0]["attack_end_timestamp"],
        )

    def test_unsorted_input_produces_deterministic_output(self) -> None:
        events = [self._event(index) for index in range(10)]
        expected = detect_brute_force(events, self._config())

        self.assertEqual(
            detect_brute_force(
                list(reversed(events)), self._config()
            ),
            expected,
        )

    def test_custom_threshold(self) -> None:
        events = [self._event(index) for index in range(3)]

        incidents = detect_brute_force(
            events, self._config(threshold=3, window=60, severity="MEDIUM")
        )

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threshold"], 3)
        self.assertEqual(incidents[0]["severity"], "MEDIUM")

    def test_custom_time_window(self) -> None:
        events = [self._event(seconds) for seconds in (0, 3, 6)]

        too_short = detect_brute_force(
            events, self._config(threshold=3, window=5)
        )
        exact_span = detect_brute_force(
            events, self._config(threshold=3, window=6)
        )

        self.assertEqual(too_short, [])
        self.assertEqual(len(exact_span), 1)

    def test_invalid_configuration_is_rejected(self) -> None:
        invalid_configs = (
            {"failed_attempt_threshold": True, "time_window_seconds": 60},
            {"failed_attempt_threshold": 10, "time_window_seconds": 0},
            {
                "failed_attempt_threshold": 10,
                "time_window_seconds": 60,
                "severity": "   ",
            },
        )

        for config in invalid_configs:
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    detect_brute_force([], config)

    def test_empty_input(self) -> None:
        self.assertEqual(detect_brute_force([], self._config()), [])

    def test_missing_usernames_are_counted_but_not_listed(self) -> None:
        events = [
            self._event(0, username="alice"),
            self._event(1, username=None),
        ]

        incidents = detect_brute_force(
            events, self._config(threshold=2, window=60)
        )

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["total_failed_attempts"], 2)
        self.assertEqual(incidents[0]["targeted_usernames"], ["alice"])

    def test_separated_attacks_produce_separate_episodes(self) -> None:
        event_times = (0, 1, 2, 30, 31, 32)
        events = [self._event(seconds) for seconds in event_times]

        incidents = detect_brute_force(
            events, self._config(threshold=3, window=10)
        )

        self.assertEqual(len(incidents), 2)
        self.assertEqual(
            [incident["total_failed_attempts"] for incident in incidents],
            [3, 3],
        )

    def test_overlapping_windows_merge_into_one_episode(self) -> None:
        events = [self._event(seconds) for seconds in range(5)]

        incidents = detect_brute_force(
            events, self._config(threshold=3, window=10)
        )

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["total_failed_attempts"], 5)

    def test_exact_window_boundary_is_inclusive(self) -> None:
        events = [self._event(0), self._event(10)]

        incidents = detect_brute_force(
            events, self._config(threshold=2, window=10)
        )

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["total_failed_attempts"], 2)


class DetectionConfigTests(unittest.TestCase):
    """Verify established config compatibility and value validation."""

    def test_existing_config_maps_severity_and_preserves_timestamp_year(
        self,
    ) -> None:
        configuration = load_detection_config()

        self.assertEqual(configuration["failed_attempt_threshold"], 10)
        self.assertEqual(configuration["time_window_seconds"], 60)
        self.assertEqual(configuration["severity"], "HIGH")
        self.assertEqual(configuration["timestamp_year"], 2026)
        self.assertEqual(configuration["default_severity"], "HIGH")

    def test_invalid_file_configuration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / "invalid.json"
            config_path.write_text(
                json.dumps(
                    {
                        "failed_attempt_threshold": 10,
                        "time_window_seconds": False,
                        "severity": "HIGH",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_detection_config(config_path)

    def test_parser_sample_integrates_with_detector(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        parsed = parse_auth_log(project_root / "samples" / "auth.log")

        self.assertIsNone(parsed["error"])
        incidents = detect_brute_force(parsed["events"])

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source_ip"], "203.0.113.10")
        self.assertEqual(incidents[0]["total_failed_attempts"], 10)


if __name__ == "__main__":
    unittest.main()

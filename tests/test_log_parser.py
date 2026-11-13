"""Unit tests for the Linux SSH authentication log parser."""

import json
import tempfile
import unittest
from pathlib import Path

from src.log_parser import (
    parse_auth_log,
    parse_log_line,
    validate_ip_address,
)


class ParseLogLineTests(unittest.TestCase):
    """Exercise supported event forms and field normalization."""

    def test_valid_failed_ssh_login(self) -> None:
        line = (
            "Nov 13 10:00:01 server01 sshd[1234]: Failed password for admin "
            "from 203.0.113.10 port 51000 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026, line_number=1)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "FAILED_LOGIN")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["source_ip"], "203.0.113.10")

    def test_invalid_user_failed_login(self) -> None:
        line = (
            "Nov 13 10:00:02 server01 sshd[1235]: Failed password for invalid "
            "user unknown_user from 198.51.100.8 port 51001 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "FAILED_LOGIN")
        self.assertEqual(event["username"], "unknown_user")

    def test_valid_successful_ssh_password_login(self) -> None:
        line = (
            "Nov 13 10:00:03 server01 sshd[1236]: Accepted password for "
            "analyst from 203.0.113.20 port 51002 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "SUCCESSFUL_LOGIN")
        self.assertEqual(event["username"], "analyst")

    def test_ipv4_validation(self) -> None:
        self.assertEqual(validate_ip_address("203.0.113.10"), "203.0.113.10")

    def test_invalid_ip_rejection(self) -> None:
        for address in (
            "256.1.1.1",
            "203.0.113.999",
            "not-an-ip",
            "2001:db8::1",
            "3405803786",
        ):
            with self.subTest(address=address):
                self.assertIsNone(validate_ip_address(address))

    def test_username_extraction_with_underscores_and_hyphens(self) -> None:
        line = (
            "Nov 13 10:00:04 server01 sshd[1237]: Failed password for "
            "build-agent_2 from 203.0.113.30 port 51003 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "build-agent_2")

    def test_timestamp_conversion_uses_configured_year(self) -> None:
        line = (
            "Nov 13 10:00:01 server01 sshd[1234]: Failed password for admin "
            "from 203.0.113.10 port 51000 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(event["timestamp"], "2026-11-13T10:00:01")

    def test_malformed_log_line_is_skipped(self) -> None:
        malformed_lines = (
            "not a syslog record",
            "Nov 13 25:61:01 server01 sshd[1234]: Failed password for admin "
            "from 203.0.113.10 port 51000 ssh2",
            "Nov 13 10:00:01 server01 sshd[1234]: Failed password for admin "
            "from 999.0.0.1 port 51000 ssh2",
        )

        for line in malformed_lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_log_line(line, timestamp_year=2026))

    def test_missing_pid_is_normalized_to_none(self) -> None:
        line = (
            "Nov 13 10:00:01 server01 sshd: Failed password for admin "
            "from 203.0.113.10 port 51000 ssh2"
        )

        event = parse_log_line(line, timestamp_year=2026)

        self.assertIsNotNone(event)
        self.assertIsNone(event["pid"])


class ParseAuthLogTests(unittest.TestCase):
    """Exercise file ingestion, counters, configuration, and errors."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    @staticmethod
    def _failed_line(username: str, seconds: int = 1) -> str:
        return (
            f"Nov 13 10:00:{seconds:02d} server01 sshd[1234]: Failed password "
            f"for {username} from 203.0.113.10 port 51000 ssh2"
        )

    def test_empty_file_handling(self) -> None:
        log_path = self.root / "empty.log"
        log_path.write_text("", encoding="utf-8")

        result = parse_auth_log(log_path, timestamp_year=2026)

        self.assertIsNone(result["error"])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["total_lines"], 0)
        self.assertEqual(result["parsed_events"], 0)
        self.assertEqual(result["skipped_lines"], 0)

    def test_multiple_records_and_skipped_count(self) -> None:
        log_path = self.root / "multiple.log"
        successful_line = (
            "Nov 13 10:00:02 server01 sshd[1235]: Accepted password "
            "for analyst "
            "from 203.0.113.20 port 51001 ssh2"
        )
        unsupported_line = (
            "Nov 13 10:00:03 server01 sshd[1236]: Accepted publickey "
            "for operator "
            "from 203.0.113.30 port 51002 ssh2"
        )
        log_path.write_text(
            "\n".join(
                [self._failed_line("admin"), successful_line, unsupported_line]
            )
            + "\n",
            encoding="utf-8",
        )

        result = parse_auth_log(log_path, timestamp_year=2026)

        self.assertIsNone(result["error"])
        self.assertEqual(result["total_lines"], 3)
        self.assertEqual(result["parsed_events"], 2)
        self.assertEqual(result["skipped_lines"], 1)
        self.assertEqual(
            [event["event_type"] for event in result["events"]],
            ["FAILED_LOGIN", "SUCCESSFUL_LOGIN"],
        )

    def test_missing_file_returns_meaningful_error(self) -> None:
        missing_path = self.root / "missing.log"

        result = parse_auth_log(missing_path, timestamp_year=2026)

        self.assertEqual(result["events"], [])
        self.assertEqual(result["total_lines"], 0)
        self.assertEqual(result["parsed_events"], 0)
        self.assertEqual(result["skipped_lines"], 0)
        self.assertIn(str(missing_path), result["error"])
        self.assertIn("Unable to read authentication log", result["error"])

    def test_line_number_and_raw_line_preservation(self) -> None:
        log_path = self.root / "line-numbers.log"
        valid_line = self._failed_line("ops_team-1", seconds=2)
        log_path.write_text(
            "malformed record\n" + valid_line + "\n", encoding="utf-8"
        )

        result = parse_auth_log(log_path, timestamp_year=2026)

        self.assertEqual(result["events"][0]["line_number"], 2)
        self.assertEqual(result["events"][0]["raw_line"], valid_line)

    def test_timestamp_year_is_loaded_from_configuration(self) -> None:
        log_path = self.root / "configured-year.log"
        config_path = self.root / "config.json"
        log_path.write_text(
            self._failed_line("admin") + "\n", encoding="utf-8"
        )
        config_path.write_text(
            json.dumps({"timestamp_year": 2025}), encoding="utf-8"
        )

        result = parse_auth_log(log_path, config_path=config_path)

        self.assertIsNone(result["error"])
        self.assertEqual(
            result["events"][0]["timestamp"], "2025-11-13T10:00:01"
        )

    def test_invalid_utf8_returns_file_error(self) -> None:
        log_path = self.root / "invalid-utf8.log"
        log_path.write_bytes(b"\xff\xfe\xfa")

        result = parse_auth_log(log_path, timestamp_year=2026)

        self.assertIn("Unable to read authentication log", result["error"])


if __name__ == "__main__":
    unittest.main()

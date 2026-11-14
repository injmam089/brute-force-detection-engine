"""Integration tests for the command-line pipeline."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.main import main


class MainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "samples").mkdir()
        self.config = self.root / "config" / "detection_config.json"
        self.input = self.root / "samples" / "auth.log"
        self.base_config = {"failed_attempt_threshold": 2, "time_window_seconds": 60, "default_severity": "HIGH", "input_file": "samples/auth.log", "timestamp_year": 2026, "output_directory": "output"}

    def prepare(self, lines=""):
        self.input.write_text(lines, encoding="utf-8")
        self.config.write_text(json.dumps(self.base_config), encoding="utf-8")
        return ["--config", str(self.config)]

    def log(self):
        return "Nov 13 10:00:00 host sshd[1]: Failed password for admin from 203.0.113.1 port 22 ssh2\nNov 13 10:00:01 host sshd[2]: Failed password for admin from 203.0.113.1 port 23 ssh2\n"

    def test_complete_pipeline(self):
        self.assertEqual(main(self.prepare(self.log())), 0)
        self.assertTrue((self.root / "output" / "security_alert.json").is_file())
        self.assertTrue((self.root / "output" / "incident_report.md").is_file())
        self.assertTrue((self.root / "output" / "mitigation_recommendations.json").is_file())
        self.assertTrue((self.root / "output" / "firewall_ban_list.md").is_file())

    def test_complete_sample_pipeline(self):
        sample_path = Path(__file__).resolve().parents[1] / "samples" / "auth.log"
        self.base_config["failed_attempt_threshold"] = 10
        self.assertEqual(main(self.prepare() + ["--input", str(sample_path)]), 0)
        alert_data = json.loads(
            (self.root / "output" / "security_alert.json").read_text()
        )
        self.assertEqual(alert_data["total_alerts"], 1)
        self.assertEqual(alert_data["alerts"][0]["source_ip"], "203.0.113.10")

    def test_empty_auth_log(self):
        self.assertEqual(main(self.prepare()), 0)

    def test_no_incidents(self):
        self.assertEqual(main(self.prepare("malformed\n")), 0)
        self.assertEqual(json.loads((self.root / "output" / "security_alert.json").read_text())["alerts"], [])

    def test_invalid_input_path(self):
        args = self.prepare()
        args += ["--input", str(self.root / "absent.log")]
        self.assertEqual(main(args), 1)

    def test_invalid_config(self):
        self.config.write_text("{}", encoding="utf-8")
        self.assertEqual(main(["--config", str(self.config)]), 1)

    def test_custom_input(self):
        args = self.prepare()
        custom = self.root / "custom.log"
        custom.write_text(self.log(), encoding="utf-8")
        args += ["--input", str(custom)]
        self.assertEqual(main(args), 0)

    def test_custom_config(self):
        three_events = (
            "Nov 13 10:00:00 host sshd[1]: Failed password for admin "
            "from 203.0.113.1 port 22 ssh2\n"
            "Nov 13 10:00:01 host sshd[2]: Failed password for admin "
            "from 203.0.113.1 port 23 ssh2\n"
            "Nov 13 10:00:03 host sshd[3]: Failed password for admin "
            "from 203.0.113.1 port 24 ssh2\n"
        )
        args = self.prepare(three_events)
        self.base_config["failed_attempt_threshold"] = 3
        self.base_config["time_window_seconds"] = 3
        self.config.write_text(json.dumps(self.base_config), encoding="utf-8")

        self.assertEqual(main(args), 0)
        alerts_path = self.root / "output" / "security_alert.json"
        alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
        self.assertEqual(alerts["total_alerts"], 1)
        self.assertEqual(alerts["alerts"][0]["threshold"], 3)
        self.assertEqual(alerts["alerts"][0]["time_window_seconds"], 3)

        self.base_config["failed_attempt_threshold"] = 4
        self.config.write_text(json.dumps(self.base_config), encoding="utf-8")
        self.assertEqual(main(args), 0)
        self.assertEqual(
            json.loads(alerts_path.read_text(encoding="utf-8"))["total_alerts"],
            0,
        )

        self.base_config["failed_attempt_threshold"] = 3
        self.base_config["time_window_seconds"] = 2
        self.config.write_text(json.dumps(self.base_config), encoding="utf-8")
        self.assertEqual(main(args), 0)
        self.assertEqual(
            json.loads(alerts_path.read_text(encoding="utf-8"))["total_alerts"],
            0,
        )

    def test_no_report(self):
        self.assertEqual(main(self.prepare(self.log()) + ["--no-report"]), 0)
        self.assertFalse((self.root / "output" / "incident_report.md").exists())

    def test_no_mitigation(self):
        self.assertEqual(main(self.prepare(self.log()) + ["--no-mitigation"]), 0)
        self.assertFalse((self.root / "output" / "mitigation_recommendations.json").exists())
        self.assertFalse((self.root / "output" / "firewall_ban_list.md").exists())

    def test_ufw_selection(self):
        self.assertEqual(main(self.prepare(self.log())), 0)
        data = json.loads((self.root / "output" / "mitigation_recommendations.json").read_text())
        self.assertIn("ufw deny", data[0]["suggested_rule"])

    def test_iptables_selection(self):
        self.assertEqual(main(self.prepare(self.log()) + ["--firewall", "iptables"]), 0)
        data = json.loads((self.root / "output" / "mitigation_recommendations.json").read_text())
        self.assertIn("iptables -I INPUT 1", data[0]["suggested_rule"])

    def test_failure_exit_code(self):
        self.assertNotEqual(main(["--config", str(self.root / "missing.json")]), 0)

    def test_alert_count_matches_incidents(self):
        self.assertEqual(main(self.prepare(self.log())), 0)
        self.assertEqual(json.loads((self.root / "output" / "security_alert.json").read_text())["total_alerts"], 1)

    def test_report_alert_id_correspondence(self):
        self.assertEqual(main(self.prepare(self.log())), 0)
        alert = json.loads((self.root / "output" / "security_alert.json").read_text())["alerts"][0]
        report = (self.root / "output" / "incident_report.md").read_text()
        self.assertIn(alert["alert_id"], report)

    def test_no_firewall_command_execution(self):
        with patch("subprocess.run", side_effect=AssertionError), patch("os.system", side_effect=AssertionError):
            self.assertEqual(main(self.prepare(self.log())), 0)

    def test_configured_output_directory(self):
        args = self.prepare(self.log())
        self.base_config["output_directory"] = "separate-results"
        self.config.write_text(json.dumps(self.base_config), encoding="utf-8")

        self.assertEqual(main(args), 0)
        output_directory = self.root / "separate-results"
        for filename in (
            "security_alert.json",
            "incident_report.md",
            "mitigation_recommendations.json",
            "firewall_ban_list.md",
        ):
            with self.subTest(filename=filename):
                self.assertTrue((output_directory / filename).is_file())
        self.assertFalse((self.root / "output").exists())

    def test_help(self):
        with self.assertRaises(SystemExit) as result:
            main(["--help"])
        self.assertEqual(result.exception.code, 0)


if __name__ == "__main__":
    unittest.main()

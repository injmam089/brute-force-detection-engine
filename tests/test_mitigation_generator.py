"""Tests for text-only firewall recommendations."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.mitigation_generator import generate_mitigation_recommendations


def sample(ip="203.0.113.1", severity="HIGH"):
    return {"source_ip": ip, "severity": severity}


class MitigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_ufw_rule(self):
        r = generate_mitigation_recommendations([sample()], self.root / "r")
        self.assertEqual(r[0]["suggested_rule"], "sudo ufw deny from 203.0.113.1 to any")

    def test_iptables_rule(self):
        r = generate_mitigation_recommendations([sample()], self.root / "r", "iptables")
        self.assertIn("iptables -A INPUT -s 203.0.113.1 -j DROP", r[0]["suggested_rule"])

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            generate_mitigation_recommendations([sample("999.0.0.1")], self.root / "r")

    def test_empty(self):
        self.assertEqual(generate_mitigation_recommendations([], self.root / "r"), [])

    def test_multiple_ips(self):
        r = generate_mitigation_recommendations([sample(), sample("198.51.100.2")], self.root / "r")
        self.assertEqual(len(r), 2)

    def test_duplicate_ip_deduplication(self):
        r = generate_mitigation_recommendations([sample(), sample()], self.root / "r")
        self.assertEqual(len(r), 1)

    def test_severity(self):
        r = generate_mitigation_recommendations([sample(severity="MEDIUM")], self.root / "r")
        self.assertEqual(r[0]["severity"], "MEDIUM")

    def test_reason(self):
        r = generate_mitigation_recommendations([sample()], self.root / "r")
        self.assertTrue(r[0]["reason"])

    def test_execution_warning(self):
        r = generate_mitigation_recommendations([sample()], self.root / "r")
        self.assertIn("review and approval", r[0]["execution_warning"])

    def test_custom_path(self):
        p = self.root / "x.json"
        generate_mitigation_recommendations([], p)
        self.assertTrue(p.is_file())

    def test_parent_created(self):
        p = self.root / "a" / "b" / "r.json"
        generate_mitigation_recommendations([], p)
        self.assertTrue(p.is_file())

    def test_invalid_firewall_type(self):
        with self.assertRaises(ValueError):
            generate_mitigation_recommendations([], self.root / "r", "nft")

    def test_invalid_structure(self):
        with self.assertRaises(ValueError):
            generate_mitigation_recommendations([{}], self.root / "r")

    def test_write_error(self):
        blocker = self.root / "file"
        blocker.write_text("x")
        with self.assertRaises(OSError):
            generate_mitigation_recommendations([], blocker / "r")

    def test_never_executes_process(self):
        with patch("subprocess.run", side_effect=AssertionError), patch("os.system", side_effect=AssertionError):
            generate_mitigation_recommendations([sample()], self.root / "r")


if __name__ == "__main__":
    unittest.main()

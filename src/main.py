"""Command-line integration for the BruteForce Sentinel pipeline."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from src.alert_generator import generate_alerts
from src.detector import detect_brute_force
from src.incident_report import generate_incident_report
from src.log_parser import parse_auth_log
from src.mitigation_generator import (
    generate_firewall_ban_list,
    generate_mitigation_recommendations,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "detection_config.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Parse SSH authentication logs and generate incident outputs.",
    )
    parser.add_argument("--input", type=Path, help="Authentication log path override.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="Detection configuration JSON.")
    parser.add_argument("--firewall", choices=("ufw", "iptables"), default="ufw", help="Recommendation format only; no commands are run.")
    parser.add_argument("--no-report", action="store_true", help="Skip Markdown report generation.")
    parser.add_argument("--no-mitigation", action="store_true", help="Skip text recommendations.")
    return parser


def run(args: argparse.Namespace) -> int:
    """Run the configured pipeline, returning a process-style exit code."""
    try:
        config_path = args.config.resolve()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a JSON object.")
        base = config_path.parent.parent
        input_path = args.input or (base / config["input_file"])
        output_directory = config["output_directory"]
        if not isinstance(output_directory, str) or not output_directory.strip():
            raise ValueError("output_directory must be a non-empty string.")
        output_path = base / output_directory

        parsed = parse_auth_log(input_path, config_path=config_path)
        if parsed["error"]:
            raise ValueError(parsed["error"])
        incidents = detect_brute_force(parsed["events"], config)
        alert_path = output_path / "security_alert.json"
        alerts_data = generate_alerts(incidents, alert_path)
        report_path = None
        if not args.no_report:
            generate_incident_report(incidents, alerts_data["alerts"], output_path / "incident_report.md")
            report_path = output_path / "incident_report.md"
        recommendations = []
        recommendation_path = None
        if not args.no_mitigation:
            recommendations = generate_mitigation_recommendations(
                incidents, output_path / "mitigation_recommendations.json", args.firewall
            )
            recommendation_path = output_path / "mitigation_recommendations.json"
            ban_list_path = output_path / "firewall_ban_list.md"
            generate_firewall_ban_list(incidents, ban_list_path)

        print(f"Lines processed: {parsed['total_lines']}")
        print(f"Events parsed: {parsed['parsed_events']}")
        print(f"Incidents detected: {len(incidents)}")
        print(f"Alerts generated: {alerts_data['total_alerts']} ({alert_path})")
        if report_path is not None:
            print(f"Incident report: {report_path}")
        if recommendation_path is not None:
            print(f"Mitigation recommendations ({args.firewall}, suggestions only): {recommendation_path}")
            print(f"Firewall ban list (suggestions only): {ban_list_path}")
        return 0
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        print(f"BruteForce Sentinel error: {error}", file=sys.stderr)
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse command-line arguments and execute the pipeline."""
    return run(_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())

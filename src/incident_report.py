"""Render detected incidents as a human-readable Markdown report."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union


_CONFIG = Path(__file__).resolve().parent.parent / "config" / "detection_config.json"
_FIELDS = ("source_ip", "severity", "attack_start_timestamp", "attack_end_timestamp", "total_failed_attempts", "targeted_usernames", "threshold", "time_window_seconds")


def _validate(incidents: Any) -> List[Dict[str, Any]]:
    if not isinstance(incidents, list):
        raise ValueError("incidents must be a list of dictionaries.")
    for index, item in enumerate(incidents):
        if not isinstance(item, dict) or any(key not in item for key in _FIELDS):
            raise ValueError(f"incident at index {index} is missing required fields.")
        if any(not isinstance(item[key], str) or not item[key].strip() for key in _FIELDS[:4]):
            raise ValueError(f"incident at index {index} has invalid text fields.")
        if not isinstance(item["targeted_usernames"], list) or any(not isinstance(name, str) for name in item["targeted_usernames"]):
            raise ValueError(f"incident at index {index} has invalid targeted_usernames.")
        for key in ("total_failed_attempts", "threshold", "time_window_seconds"):
            value = item[key]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"incident at index {index} has invalid {key}.")
    return incidents


def _default_path() -> Path:
    try:
        config = json.loads(_CONFIG.read_text(encoding="utf-8"))
        directory = config["output_directory"]
        if not isinstance(directory, str) or not directory.strip():
            raise ValueError("output_directory must be a non-empty string.")
        return _CONFIG.parent.parent / directory / "incident_report.md"
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as error:
        raise ValueError(f"Unable to load output_directory: {error}") from error


def generate_incident_report(
    incidents: Sequence[Dict[str, Any]], alerts: Optional[Sequence[Dict[str, Any]]] = None,
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Generate and optionally write a Markdown report from actual incidents."""
    records = _validate(incidents)
    if alerts is not None:
        if not isinstance(alerts, list) or any(not isinstance(a, dict) or not isinstance(a.get("alert_id"), str) for a in alerts):
            raise ValueError("alerts must be a list of alert dictionaries with alert_id values.")
    alert_by_incident = {}
    if alerts:
        for alert in alerts:
            key = (alert.get("source_ip"), alert.get("attack_start_timestamp"), alert.get("attack_end_timestamp"))
            alert_by_incident.setdefault(key, []).append(alert["alert_id"])
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = ["# BruteForce Sentinel Incident Report", "", f"Generated: {generated}", "", f"Total incidents: {len(records)}", ""]
    if not records:
        lines.extend([
            "No incidents were detected.",
            "",
            "## Incident-Response Triage Summary",
            "",
            "No detector evidence is available for triage.",
        ])
    else:
        lines.extend(["## Severity distribution", ""])
        for severity, count in sorted(Counter(item["severity"] for item in records).items()):
            lines.append(f"- {severity}: {count}")
        lines.extend(["", "## Observations", "", f"The supplied detection results contain {len(records)} incident episode(s).", "", "## Incidents"])
        for number, item in enumerate(records, 1):
            lines.extend([
                "", f"### Incident {number}", "", f"- Source IP: `{item['source_ip']}`",
                f"- Severity: {item['severity']}", f"- Attack start: {item['attack_start_timestamp']}",
                f"- Attack end: {item['attack_end_timestamp']}",
                f"- Failed attempts: {item['total_failed_attempts']}",
                f"- Targeted usernames: {', '.join(item['targeted_usernames']) or 'None supplied'}",
                f"- Threshold: {item['threshold']} attempts", f"- Time window: {item['time_window_seconds']} seconds",
            ])
            key = (item["source_ip"], item["attack_start_timestamp"], item["attack_end_timestamp"])
            ids = alert_by_incident.get(key, [])
            if ids:
                lines.append(f"- Alert ID: {', '.join(ids)}")
            lines.extend(["", "**Analyst interpretation:** The supplied detector output reports repeated failed SSH authentication from this source within the configured window."])
        lines.extend([
            "", "## Recommendations", "",
            "These are review steps, not automated actions:",
            "- Review authentication logs around each reported interval.",
            "- Validate whether the source activity is legitimate.",
            "- Check the affected accounts and authentication history.",
            "- Escalate confirmed incidents according to local procedures.",
            "",
            "## Incident-Response Triage Summary",
            "",
            "The following summaries are evidence-based investigation leads. A detection alert does not by itself prove malicious activity.",
        ])
        for number, item in enumerate(records, 1):
            key = (
                item["source_ip"],
                item["attack_start_timestamp"],
                item["attack_end_timestamp"],
            )
            alert_ids = alert_by_incident.get(key, [])
            lines.extend([
                "",
                f"### Triage {number}",
                "",
                f"- Detected source IP: `{item['source_ip']}`",
                f"- Severity: {item['severity']}",
                f"- Attack interval: {item['attack_start_timestamp']} to {item['attack_end_timestamp']}",
                f"- Failed attempt count: {item['total_failed_attempts']}",
                f"- Detection threshold: {item['threshold']} attempts in {item['time_window_seconds']} seconds",
                f"- Targeted usernames: {', '.join(item['targeted_usernames']) or 'None supplied'}",
                f"- Related alert ID: {', '.join(alert_ids) if alert_ids else 'No associated alert ID'}",
                "- Review and validation: compare the interval with SSH, VPN, identity, and change-management records; verify whether the source and targeted accounts are expected.",
                "- Evidence preservation: retain the original authentication-log lines and relevant system, network, and identity records before rotation or remediation.",
                "- Escalation: notify the designated security owner when validation indicates unauthorized or high-risk activity, following local incident procedures.",
                "- Authorized containment: after administrator review, consider the separately generated UFW or iptables suggestions; do not apply a block automatically.",
            ])
    report = "\n".join(lines).rstrip() + "\n"
    destination = Path(output_path) if output_path is not None else _default_path()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
    except OSError as error:
        raise OSError(f"Unable to write incident report to '{destination}': {error}") from error
    return report

"""Build structured JSON alerts from detected incident episodes."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union


_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "detection_config.json"
)
_REQUIRED_FIELDS = (
    "severity",
    "source_ip",
    "attack_start_timestamp",
    "attack_end_timestamp",
    "total_failed_attempts",
    "targeted_usernames",
    "threshold",
    "time_window_seconds",
)


def _load_output_directory() -> Path:
    """Read the configured output directory without duplicating its value."""
    try:
        with _CONFIG_PATH.open("r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Unable to load output_directory from '{_CONFIG_PATH}': {error}"
        ) from error

    output_directory = config.get("output_directory") if isinstance(config, dict) else None
    if not isinstance(output_directory, str) or not output_directory.strip():
        raise ValueError(
            f"Configuration '{_CONFIG_PATH}' must define a non-empty output_directory."
        )
    return _CONFIG_PATH.parent.parent / output_directory


def _validate_incidents(incidents: Any) -> List[Dict[str, Any]]:
    """Validate incident dictionaries before producing any alerts."""
    if not isinstance(incidents, list):
        raise ValueError("incidents must be a list of incident dictionaries.")

    for index, incident in enumerate(incidents):
        if not isinstance(incident, dict):
            raise ValueError(f"incident at index {index} must be a dictionary.")
        missing = [field for field in _REQUIRED_FIELDS if field not in incident]
        if missing:
            raise ValueError(
                f"incident at index {index} is missing required fields: "
                f"{', '.join(missing)}."
            )
        for field in ("severity", "source_ip", "attack_start_timestamp", "attack_end_timestamp"):
            if not isinstance(incident[field], str) or not incident[field].strip():
                raise ValueError(
                    f"incident at index {index} has invalid {field}; "
                    "expected a non-empty string."
                )
        for field in ("total_failed_attempts", "threshold", "time_window_seconds"):
            value = incident[field]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(
                    f"incident at index {index} has invalid {field}; "
                    "expected a positive integer."
                )
        usernames = incident["targeted_usernames"]
        if not isinstance(usernames, list) or any(
            not isinstance(username, str) for username in usernames
        ):
            raise ValueError(
                f"incident at index {index} has invalid targeted_usernames; "
                "expected a list of strings."
            )
    return incidents


def generate_alerts(
    incidents: Sequence[Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Generate one JSON alert per validated detector incident.

    The returned object matches the written JSON payload. If ``output_path``
    is omitted, ``security_alert.json`` is written under the configured output
    folder.
    """
    validated_incidents = _validate_incidents(incidents)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    alerts: List[Dict[str, Any]] = []
    for incident in validated_incidents:
        alert = {
            "alert_id": str(uuid.uuid4()),
            "alert_type": "BRUTE_FORCE_DETECTED",
            "severity": incident["severity"],
            "status": "OPEN",
            "source_ip": incident["source_ip"],
            "attack_start_timestamp": incident["attack_start_timestamp"],
            "attack_end_timestamp": incident["attack_end_timestamp"],
            "total_failed_attempts": incident["total_failed_attempts"],
            "targeted_usernames": incident["targeted_usernames"],
            "threshold": incident["threshold"],
            "time_window_seconds": incident["time_window_seconds"],
            "detected_at": generated_at,
        }
        alerts.append(alert)

    alert_data = {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "total_alerts": len(alerts),
        "alerts": alerts,
    }
    destination = (
        Path(output_path)
        if output_path is not None
        else _load_output_directory() / "security_alert.json"
    )
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as output_file:
            json.dump(alert_data, output_file, indent=2, sort_keys=True)
            output_file.write("\n")
    except OSError as error:
        raise OSError(f"Unable to write alerts to '{destination}': {error}") from error
    return alert_data

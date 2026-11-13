"""Correlate SSH authentication failures into brute-force episodes."""

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.log_parser import validate_ip_address


_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "detection_config.json"
)
_DEFAULT_SEVERITY = "HIGH"


def _positive_integer(value: Any, name: str) -> int:
    """Validate a positive integer while explicitly rejecting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def _normalize_severity(value: Any) -> str:
    """Validate and normalize a configured severity label."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("severity must be a non-empty string.")
    return value.strip().upper()


def _validate_detection_config(
    configuration: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate detector settings and retain compatible parser settings."""
    if not isinstance(configuration, Mapping):
        raise ValueError("Detection configuration must be a JSON object.")

    validated = dict(configuration)
    validated["failed_attempt_threshold"] = _positive_integer(
        configuration.get("failed_attempt_threshold"),
        "failed_attempt_threshold",
    )
    validated["time_window_seconds"] = _positive_integer(
        configuration.get("time_window_seconds"), "time_window_seconds"
    )

    severity_values = []
    for key in ("severity", "default_severity"):
        if key in configuration:
            severity_values.append(
                (key, _normalize_severity(configuration[key]))
            )
    if (
        len(severity_values) == 2
        and severity_values[0][1] != severity_values[1][1]
    ):
        raise ValueError(
            "severity and default_severity specify conflicting values."
        )
    validated["severity"] = (
        severity_values[0][1] if severity_values else _DEFAULT_SEVERITY
    )

    # Keep parser configuration in the same mapping and validate its year so
    # parser and detector continue to consume one consistent JSON file.
    if "timestamp_year" in configuration:
        _positive_integer(configuration["timestamp_year"], "timestamp_year")
        if configuration["timestamp_year"] > 9999:
            raise ValueError("timestamp_year must be from 1 through 9999.")

    for key in ("input_file", "output_directory"):
        if key in configuration and (
            not isinstance(configuration[key], str)
            or not configuration[key].strip()
        ):
            raise ValueError(f"{key} must be a non-empty string.")

    return validated


def load_detection_config(
    config_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Load and validate detector settings from the project JSON config.

    The existing project schema calls the severity field ``default_severity``.
    It is exposed as the canonical ``severity`` value, while a ``severity``
    field is also accepted for future configuration files. Other settings,
    including ``timestamp_year``, are retained for parser compatibility.
    """
    path = (
        Path(config_path)
        if config_path is not None
        else _DEFAULT_CONFIG_PATH
    )
    try:
        with path.open("r", encoding="utf-8") as config_file:
            configuration = json.load(config_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Unable to load detection configuration '{path}': {error}"
        ) from error

    if not isinstance(configuration, dict):
        raise ValueError(
            f"Invalid detection configuration '{path}': "
            "expected a JSON object."
        )
    return _validate_detection_config(configuration)


def group_failed_events(
    events: Iterable[Mapping[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group failed-login events by validated IPv4 source address.

    Successful events, malformed items, and events with missing or invalid
    source addresses are ignored. Returned source keys are sorted.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if event.get("event_type") != "FAILED_LOGIN":
            continue

        source_ip = validate_ip_address(event.get("source_ip"))
        if source_ip is None:
            continue
        grouped.setdefault(source_ip, []).append(dict(event))

    return {source_ip: grouped[source_ip] for source_ip in sorted(grouped)}


def _parse_event_timestamp(value: Any) -> Optional[datetime]:
    """Parse an ISO timestamp and normalize offset-aware values to UTC."""
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None

    if timestamp.tzinfo is not None and timestamp.utcoffset() is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp


def _format_timestamp(timestamp: datetime) -> str:
    """Return a stable ISO 8601 timestamp without unnecessary fractions."""
    if timestamp.microsecond:
        return timestamp.isoformat()
    return timestamp.isoformat(timespec="seconds")


def correlate_source_ip(
    source_ip: str,
    events: Iterable[Mapping[str, Any]],
    threshold: int,
    time_window_seconds: int,
    severity: str = _DEFAULT_SEVERITY,
) -> List[Dict[str, Any]]:
    """Find and merge qualifying sliding-window episodes for one source IP."""
    validated_ip = validate_ip_address(source_ip)
    if validated_ip is None:
        return []
    threshold = _positive_integer(threshold, "threshold")
    time_window_seconds = _positive_integer(
        time_window_seconds, "time_window_seconds"
    )
    severity = _normalize_severity(severity)

    timed_events: List[Tuple[datetime, Dict[str, Any]]] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if event.get("event_type") != "FAILED_LOGIN":
            continue
        if validate_ip_address(event.get("source_ip")) != validated_ip:
            continue
        timestamp = _parse_event_timestamp(event.get("timestamp"))
        if timestamp is None:
            continue
        timed_events.append((timestamp, dict(event)))

    timed_events.sort(key=lambda item: item[0])
    if not timed_events:
        return []

    timestamps = [item[0] for item in timed_events]
    max_window = timedelta(seconds=time_window_seconds)
    detection_intervals: List[Dict[str, int]] = []
    left = 0

    # Each qualifying right edge creates an interval spanning its active
    # window. The left pointer advances monotonically, keeping the scan linear.
    for right, current_timestamp in enumerate(timestamps):
        while current_timestamp - timestamps[left] > max_window:
            left += 1

        if right - left + 1 < threshold:
            continue

        if (
            detection_intervals
            and timestamps[left]
            <= timestamps[detection_intervals[-1]["end_index"]]
        ):
            detection_intervals[-1]["end_index"] = right
        else:
            detection_intervals.append(
                {"start_index": left, "end_index": right}
            )

    incidents: List[Dict[str, Any]] = []
    for interval in detection_intervals:
        start_index = interval["start_index"]
        end_index = interval["end_index"]
        episode_events = timed_events[start_index : end_index + 1]
        usernames = {
            username.strip()
            for _, event in episode_events
            if isinstance((username := event.get("username")), str)
            and username.strip()
        }

        incidents.append(
            {
                "source_ip": validated_ip,
                "attack_start_timestamp": _format_timestamp(
                    timestamps[start_index]
                ),
                "attack_end_timestamp": _format_timestamp(
                    timestamps[end_index]
                ),
                "total_failed_attempts": len(episode_events),
                "targeted_usernames": sorted(usernames),
                "threshold": threshold,
                "time_window_seconds": time_window_seconds,
                "severity": severity,
            }
        )

    return incidents


def detect_brute_force(
    events: Iterable[Mapping[str, Any]],
    config: Optional[Mapping[str, Any]] = None,
    config_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Detect source-IP brute-force episodes using validated settings.

    When ``config`` is omitted, settings are loaded from the project config
    or the supplied ``config_path``. A custom mapping is validated in the same
    way. The function returns incident dictionaries and performs no output
    file generation or system mitigation.
    """
    detection_config = (
        load_detection_config(config_path)
        if config is None
        else _validate_detection_config(config)
    )
    grouped_events = group_failed_events(events)
    incidents: List[Dict[str, Any]] = []

    for source_ip in sorted(grouped_events):
        incidents.extend(
            correlate_source_ip(
                source_ip=source_ip,
                events=grouped_events[source_ip],
                threshold=detection_config["failed_attempt_threshold"],
                time_window_seconds=detection_config["time_window_seconds"],
                severity=detection_config["severity"],
            )
        )

    return incidents

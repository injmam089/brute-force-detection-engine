"""Parse Linux SSH authentication log records into normalized events."""

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union


_MONTH_NUMBERS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_RECORD_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)
_USERNAME_PATTERN = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_FAILED_PATTERN = re.compile(
    rf"^Failed password for (?:invalid user\s+)?"
    rf"(?P<username>{_USERNAME_PATTERN})\s+from\s+(?P<source_ip>\S+)(?:\s|$)"
)
_SUCCESS_PATTERN = re.compile(
    rf"^Accepted password for (?P<username>{_USERNAME_PATTERN})\s+"
    rf"from\s+(?P<source_ip>\S+)(?:\s|$)"
)
_IPV4_TEXT_PATTERN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}\Z")
_DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "detection_config.json"
)


def validate_ip_address(address: str) -> Optional[str]:
    """Return a canonical IPv4 address, or ``None`` when it is invalid.

    Only dotted-quad IPv4 text is accepted. The standard-library ``ipaddress``
    module performs the range and component validation.
    """
    if not isinstance(address, str) or not _IPV4_TEXT_PATTERN.fullmatch(
        address
    ):
        return None

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return None

    if not isinstance(parsed_address, ipaddress.IPv4Address):
        return None
    return str(parsed_address)


def normalize_event(
    timestamp: datetime,
    hostname: Optional[str],
    service: str,
    pid: Optional[int],
    event_type: str,
    username: Optional[str],
    source_ip: Optional[str],
    raw_line: str,
    line_number: int,
) -> Dict[str, Any]:
    """Create a consistently shaped authentication event dictionary."""
    return {
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "hostname": hostname,
        "service": service,
        "pid": pid,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "raw_line": raw_line,
        "line_number": line_number,
    }


def parse_log_line(
    line: str, timestamp_year: int, line_number: int = 1
) -> Optional[Dict[str, Any]]:
    """Parse one supported SSH password-authentication record.

    The input line's original contents are retained in ``raw_line`` without
    its platform line terminator. Unsupported or malformed records return
    ``None``.
    """
    raw_line = line.rstrip("\r\n")
    record_match = _RECORD_PATTERN.fullmatch(raw_line)
    if record_match is None:
        return None

    fields = record_match.groupdict()
    month_number = _MONTH_NUMBERS.get(fields["month"])
    if month_number is None:
        return None

    try:
        timestamp = datetime(
            timestamp_year,
            month_number,
            int(fields["day"]),
            int(fields["hour"]),
            int(fields["minute"]),
            int(fields["second"]),
        )
        pid = int(fields["pid"]) if fields["pid"] is not None else None
    except (OverflowError, ValueError):
        return None

    message = fields["message"]
    event_match = _FAILED_PATTERN.match(message)
    if event_match is not None:
        event_type = "FAILED_LOGIN"
    else:
        event_match = _SUCCESS_PATTERN.match(message)
        if event_match is None:
            return None
        event_type = "SUCCESSFUL_LOGIN"

    source_ip = validate_ip_address(event_match.group("source_ip"))
    if source_ip is None:
        return None

    return normalize_event(
        timestamp=timestamp,
        hostname=fields["hostname"],
        service="sshd",
        pid=pid,
        event_type=event_type,
        username=event_match.group("username"),
        source_ip=source_ip,
        raw_line=raw_line,
        line_number=line_number,
    )


def _load_timestamp_year(
    config_path: Union[str, Path],
) -> Tuple[Optional[int], Optional[str]]:
    """Load and validate ``timestamp_year`` from a JSON configuration file."""
    path = Path(config_path)
    try:
        with path.open("r", encoding="utf-8") as config_file:
            configuration = json.load(config_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"Unable to load timestamp year from '{path}': {error}"

    if not isinstance(configuration, dict):
        return None, (
            f"Invalid configuration in '{path}': expected a JSON object."
        )

    year = configuration.get("timestamp_year")
    if (
        isinstance(year, bool)
        or not isinstance(year, int)
        or not 1 <= year <= 9999
    ):
        return None, (
            f"Invalid or missing timestamp_year in '{path}'; "
            "expected an integer "
            "from 1 through 9999."
        )
    return year, None


def parse_auth_log(
    log_path: Union[str, Path],
    timestamp_year: Optional[int] = None,
    config_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Parse a UTF-8 authentication log and return events and processing stats.

    If ``timestamp_year`` is omitted, it is read from the project's
    ``config/detection_config.json`` or from ``config_path`` when supplied.
    File and configuration errors are returned in the ``error`` field instead
    of being raised. Unsupported and malformed lines count as skipped lines.
    """
    result: Dict[str, Any] = {
        "events": [],
        "total_lines": 0,
        "parsed_events": 0,
        "skipped_lines": 0,
        "error": None,
    }

    if timestamp_year is None:
        selected_config = config_path or _DEFAULT_CONFIG_PATH
        timestamp_year, config_error = _load_timestamp_year(selected_config)
        if config_error is not None:
            result["error"] = config_error
            return result
    elif (
        isinstance(timestamp_year, bool)
        or not isinstance(timestamp_year, int)
        or not 1 <= timestamp_year <= 9999
    ):
        result["error"] = (
            "timestamp_year must be an integer from 1 through 9999."
        )
        return result

    path = Path(log_path)
    try:
        with path.open("r", encoding="utf-8") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                result["total_lines"] += 1
                event = parse_log_line(line, timestamp_year, line_number)
                if event is None:
                    result["skipped_lines"] += 1
                else:
                    result["events"].append(event)
                    result["parsed_events"] += 1
    except (OSError, UnicodeError) as error:
        result["error"] = (
            f"Unable to read authentication log '{path}': {error}"
        )

    return result

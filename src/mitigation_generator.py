"""Generate reviewed firewall command suggestions without executing them."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from src.log_parser import validate_ip_address

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "detection_config.json"


def _default_path() -> Path:
    try:
        config = json.loads(_CONFIG.read_text(encoding="utf-8"))
        directory = config["output_directory"]
        if not isinstance(directory, str) or not directory.strip():
            raise ValueError("output_directory must be a non-empty string.")
        return _CONFIG.parent.parent / directory / "mitigation_recommendations.json"
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as error:
        raise ValueError(f"Unable to load output_directory: {error}") from error


def generate_mitigation_recommendations(
    incidents: Sequence[Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
    firewall_type: str = "ufw",
) -> List[Dict[str, str]]:
    """Return and write safe rule suggestions; never execute a command."""
    if firewall_type not in ("ufw", "iptables"):
        raise ValueError("firewall_type must be 'ufw' or 'iptables'.")
    if not isinstance(incidents, list):
        raise ValueError("incidents must be a list of incident dictionaries.")
    recommendations: List[Dict[str, str]] = []
    seen = set()
    for index, incident in enumerate(incidents):
        if not isinstance(incident, dict) or "source_ip" not in incident:
            raise ValueError(f"incident at index {index} must include source_ip.")
        if "severity" not in incident or not isinstance(incident["severity"], str):
            raise ValueError(f"incident at index {index} must include severity.")
        source_ip = validate_ip_address(incident["source_ip"])
        if source_ip is None:
            raise ValueError(f"incident at index {index} has an invalid source_ip.")
        if source_ip in seen:
            continue
        seen.add(source_ip)
        rule = (
            f"sudo ufw deny from {source_ip} to any"
            if firewall_type == "ufw"
            else f"sudo iptables -A INPUT -s {source_ip} -j DROP"
        )
        recommendations.append({
            "source_ip": source_ip,
            "severity": incident["severity"],
            "reason": "Repeated failed SSH authentication was detected from this source.",
            "firewall_type": firewall_type,
            "suggested_rule": rule,
            "execution_warning": "Suggestion only; administrator review and approval are required. This IP has not been blocked.",
        })

    destination = Path(output_path) if output_path is not None else _default_path()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(recommendations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        raise OSError(f"Unable to write mitigation recommendations to '{destination}': {error}") from error
    return recommendations

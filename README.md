# BruteForce Sentinel

BruteForce Sentinel is a defensive educational project that parses synthetic Linux SSH authentication logs, detects repeated failed logins by source IP, and prepares incident outputs for analyst review. It is not a real-time monitor or production security product.

## Problem and objectives

Repeated SSH password failures can indicate account guessing. This project demonstrates a modular workflow for parsing authorized log data, correlating failures over time, creating structured alerts, writing a human-readable report, and suggesting reviewed response steps.

## Features

- Parses supported SSH failed-password and successful-password records.
- Correlates failed events by validated IPv4 source and configured time window.
- Generates JSON alerts, Markdown incident summaries, and text-only firewall suggestions.
- Provides a command-line pipeline with input, configuration, and output controls.
- Uses synthetic documentation-range IP addresses in its sample log.

## Architecture

```text
auth.log -> log_parser -> detector -> alert_generator
                              |             |
                              +-> incident_report
                              +-> mitigation_generator (text suggestions only)
```

## Structure

```text
src/       Parser, detector, alert/report/recommendation modules, CLI
config/    Detection settings
samples/   Synthetic SSH authentication log
output/    Generated local artifacts
tests/     unittest suites
```

## Technology and setup

Python 3.10 or newer is recommended. The project uses only the Python standard library; no package installation is required. From the project directory:

```powershell
python --version
python -m unittest discover -s tests -v
```

## Configuration

`config/detection_config.json` contains `failed_attempt_threshold` (positive integer), `time_window_seconds` (positive integer), `default_severity`, `timestamp_year`, `input_file`, and `output_directory`. The detector exposes `default_severity` as its canonical severity value. The parser uses `timestamp_year` to expand syslog timestamps.

## Usage

```powershell
python -m src.main
python -m src.main --help
python -m src.main --input samples/auth.log --firewall ufw
python -m src.main --firewall iptables --no-report
python -m src.main --no-mitigation
```

CLI options: `--input PATH` overrides the configured log; `--config PATH` selects configuration; `--firewall` chooses `ufw` or `iptables` recommendation syntax; `--no-report` and `--no-mitigation` skip those outputs. Alerts are written to `output/alerts.json`; reports and recommendation JSON are written under the configured output directory.

## Outputs

The alert JSON has a schema version, generation timestamp, count, and alert list. Alerts include UUIDs, severity, source, incident bounds, failed-attempt count, usernames, threshold, and window. The Markdown report summarizes observed detector results and separates them from analyst recommendations. Firewall output contains source IP, severity, reason, suggested rule, and an execution warning. Suggestions require administrator review; the program never runs them and never claims an address was blocked.

Sample behavior on the checked-in synthetic log: 24 lines are processed, 20 supported events are parsed (19 failed-password events and 1 successful-password event), 4 unsupported or malformed lines are skipped, and the configured detector identifies one incident from `203.0.113.10`. Actual alert IDs and timestamps vary per run.

## Security considerations and limitations

Use only logs you are authorized to analyze. Input files can contain sensitive account information; protect generated artifacts accordingly. The sample uses documentation-only addresses. Detection is based on the implemented password-event formats and configured time window; it does not inspect network traffic, validate whether activity is malicious, or apply firewall changes. Recommendations are text for human review only.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Future improvements

Possible educational extensions include broader log-format fixtures, richer configuration validation, and additional report formats. These are not claims about current functionality.

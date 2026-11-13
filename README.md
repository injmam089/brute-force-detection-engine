# BruteForce Sentinel

BruteForce Sentinel is an educational project foundation for a planned automated incident alerting and brute-force detection engine.

## Objectives

- Prepare a clear, modular project structure.
- Plan for analysis of Linux SSH authentication logs.
- Establish configuration and synthetic sample data for later development.
- Keep detection, alerting, and mitigation functionality out of this foundation phase.

## Technology stack

Python standard library only. The planned implementation may use `re`, `datetime`, `json`, `collections`, `pathlib`, `argparse`, `csv`, `ipaddress`, and `unittest`. No third-party dependencies are required at this phase.

## Planned architecture

- `src/log_parser.py`: planned log reading and event parsing.
- `src/detector.py`: planned time-window analysis for repeated failed logins.
- `src/alert_generator.py`: planned alert formatting and output.
- `src/mitigation_generator.py`: planned mitigation recommendations; no firewall execution is planned.
- `src/main.py`: planned command-line entry point.

These are planned responsibilities; the modules are currently placeholders.

## Project structure

```text
BruteForce-Sentinel/
├── src/                 # Placeholder application modules
├── config/              # Runtime configuration
├── samples/             # Synthetic SSH authentication log
├── output/              # Reserved for future generated output
├── tests/               # Reserved for future tests
├── screenshots/         # Reserved for project screenshots
├── requirements.txt
└── README.md
```

## Detection concept

The planned engine will evaluate failed SSH authentication events by source and time window against configurable thresholds. This concept is not implemented in the current phase.

## Current development phase

**Phase 0 — Project foundation.** The repository structure, starter configuration, and synthetic log fixture are established. Parsing, detection, alert generation, and mitigation functionality have not been implemented.

## Disclaimer

This project is intended for educational use with synthetic or otherwise authorized log data. It is not a substitute for a production security monitoring system.
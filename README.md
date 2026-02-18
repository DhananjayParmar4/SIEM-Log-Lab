# SIEM Log Lab – SOC Simulation

This project simulates a Security Operations Center (SOC) environment using Python.

## Features

- Detects brute force attacks
- Detects brute force attacks within time windows
- Detects password spraying across multiple accounts
- Assigns severity levels: Low, Medium, High
- Generates professional incident reports
- Handles multiple attackers (IP addresses) simultaneously

## Usage

1. Update `logs/sample_logs.txt` with login events
2. Run scripts from `scripts/` folder, e.g.:

```bash
python3 scripts/parse_logs_password_spray_incident.py

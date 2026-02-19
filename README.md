# SIEM-Log-Lab – SOC Simulation

This project simulates a Security Operations Center (SOC) environment using Python to detect common security incidents.

## Features

- Detects **Brute Force attacks**
- Detects **Password Spraying attempts**
- Detects **Web-based attacks** (SQL Injection, Phishing)
- Assigns severity levels: Low, Medium, High
- Generates professional incident reports
- Handles multiple attackers (IP addresses) simultaneously
- Merges all alerts into a **master incident report**

## Folder Structure

SIEM-Log-Lab/
├── logs/
│   ├── sample_logs.txt                  # Input log file
│   ├── brute_force_report.txt           # Generated brute force report
│   ├── password_spray_report.txt        # Generated password spraying report
│   ├── web_attack_report.txt            # Generated web attack report
│   └── master_incident_report.txt       # Master report merging all alerts
├── scripts/
│   ├── parse_logs_v1.py                 # Brute force detection
│   ├── parse_logs_password_spray_incident.py  # Password spraying detection
│   ├── web_attack_detector.py           # Web attacks detection
│   ├── merge_reports.py                 # Merge all reports
│   └── run_all.py                       # Run all scripts and update master report
└── README.md

## How to Run

### Run individual scripts

```bash
# Brute Force detection
python3 scripts/parse_logs_v1.py

# Password Spraying detection
python3 scripts/parse_logs_password_spray_incident.py

# Web Attack detection
python3 scripts/web_attack_detector.py

# Merge all reports
python3 scripts/merge_reports.py
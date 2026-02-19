#!/usr/bin/env python3

print("SCRIPT STARTED")

import os

print("=== Web Attack Detection Report ===\n")

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_file = os.path.join(BASE_DIR, "logs", "sample_logs.txt")
report_file = os.path.join(BASE_DIR, "logs", "web_attack_report.txt")

# Prepare report lines
report_lines = []

# Check if log exists
if not os.path.exists(log_file):
    print(f"Error: Log file not found at {log_file}")
    exit(1)

# Open log and analyze
with open(log_file, "r") as f:
    for line in f:
        line = line.strip()
        print("Checking line:", line)

        # --- SQL Injection detection ---
        lower_line = line.lower()
        if "' or '1'='1" in lower_line or "drop table" in lower_line or "--" in lower_line or "' or 1=1" in lower_line:
            ip = "Unknown"
            if "IP" in line:
                ip = line.split("IP")[1].split("|")[0].strip()
            msg = f"ALERT: SQL Injection attempt detected from IP {ip} | Severity: High"
            print(msg)
            report_lines.append(msg)

        # --- Phishing detection ---
        if "Email click" in line and "URL:" in line:
            user = line.split("from")[1].split("|")[0].strip()
            url = line.split("URL:")[1].strip()
            if "company.com" not in url:
                msg = f"ALERT: Possible phishing link clicked by {user} | Severity: Medium"
                print(msg)
                report_lines.append(msg)

# Save report
with open(report_file, "w") as rf:
    rf.write("=== Web Attack Detection Report ===\n\n")
    if report_lines:
        for r in report_lines:
            rf.write(r + "\n")
    else:
        rf.write("No web-based threats detected.\n")

print(f"\nReport saved to {report_file}")
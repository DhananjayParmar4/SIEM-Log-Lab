from collections import defaultdict
import os

# Dictionary to store failed login attempts per IP
failed_attempts = defaultdict(int)

# Open log file
with open("logs/sample_logs.txt", "r") as file:
    for line in file:
        if "Failed login" in line:
            # Extract IP (assuming format: ... from IP 192.168.1.10)
            parts = line.strip().split("IP")
            if len(parts) > 1:
                ip = parts[1].strip()
                failed_attempts[ip] += 1

# Define threshold
THRESHOLD = 3

print("=== Brute Force Detection Report ===\n")

# Prepare report lines
report_lines = []
for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        msg = f"ALERT: Possible brute force attack from IP {ip} ({count} failed attempts)"
    else:
        msg = f"INFO: {ip} had {count} failed attempts"
    print(msg)
    report_lines.append(msg)

# Ensure logs folder exists
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

# Save to brute force report
BRUTE_REPORT_FILE = os.path.join(BASE_DIR, "logs", "brute_force_report.txt")
with open(BRUTE_REPORT_FILE, "w") as bf:
    if report_lines:
        for line in report_lines:
            bf.write(line + "\n")
    else:
        bf.write("No brute force attacks detected.\n")

print(f"Brute Force report saved to {BRUTE_REPORT_FILE}")
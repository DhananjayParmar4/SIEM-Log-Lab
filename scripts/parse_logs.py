from collections import defaultdict
from datetime import datetime, timedelta
import re

# Thresholds
THRESHOLD = 3  # failed attempts
TIME_WINDOW_MINUTES = 2  # time window in minutes

# Store timestamps of failed logins per IP
failed_attempts = defaultdict(list)

# Open log file
with open("logs/sample_logs.txt", "r") as file:
    for line in file:
        if "Failed login" in line:
            # Extract timestamp and IP
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}) .*IP (.+)", line)
            if match:
                timestamp_str = match.group(1)
                ip = match.group(2).strip()
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M")
                failed_attempts[ip].append(timestamp)

print("=== Brute Force Detection Report with Time Window ===\n")

for ip, times in failed_attempts.items():
    # Sort timestamps
    times.sort()
    alert_triggered = False

    # Check sliding window
    for i in range(len(times)):
        window_start = times[i]
        window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)
        count = sum(1 for t in times if window_start <= t <= window_end)
        if count >= THRESHOLD:
            print(f"ALERT: Possible brute force attack from IP {ip} ({count} failed attempts in {TIME_WINDOW_MINUTES} minutes)")
            alert_triggered = True
            break
    if not alert_triggered:
        print(f"INFO: {ip} had {len(times)} failed attempts, below threshold")
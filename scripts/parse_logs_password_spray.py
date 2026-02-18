from collections import defaultdict
from datetime import datetime, timedelta
import re

# Thresholds
USERNAME_THRESHOLD = 3  # failed attempts on different usernames
TIME_WINDOW_MINUTES = 2  # optional

# Store failed attempts per IP per username
failed_attempts = defaultdict(set)
timestamps = defaultdict(list)

# Open log file
with open("logs/sample_logs.txt", "r") as file:
    for line in file:
        if "Failed login" in line:
            # Extract timestamp, IP, username
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}) Failed login for user (\S+) from IP (.+)", line)
            if match:
                timestamp_str = match.group(1)
                username = match.group(2).strip()
                ip = match.group(3).strip()
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M")

                failed_attempts[ip].add(username)
                timestamps[ip].append(timestamp)

print("=== Password Spraying Detection Report ===\n")

for ip, users in failed_attempts.items():
    if len(users) >= USERNAME_THRESHOLD:
        print(f"ALERT: Possible password spraying from IP {ip} ({len(users)} usernames targeted)")
    else:
        print(f"INFO: {ip} targeted {len(users)} usernames, below threshold")
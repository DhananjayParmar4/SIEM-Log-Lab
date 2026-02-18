from collections import defaultdict
from datetime import datetime
import re

# Thresholds
USERNAME_THRESHOLD = 3  # failed attempts on different usernames

# Severity levels
def severity_level(count):
    if count < 3:
        return "Low"
    elif count <= 4:
        return "Medium"
    else:
        return "High"

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

print("=== Password Spraying Detection Report with Severity ===\n")

report_lines = []

for ip, users in failed_attempts.items():
    count = len(users)
    sev = severity_level(count)
    last_attempt = max(timestamps[ip]).strftime("%Y-%m-%d %H:%M")
    attack_type = "Password Spraying" if count >= USERNAME_THRESHOLD else "Failed Login"
    
    if count >= USERNAME_THRESHOLD:
        msg = f"ALERT: {attack_type} from IP {ip} ({count} usernames) | Severity: {sev} | Last Attempt: {last_attempt}"
    else:
        msg = f"INFO: {ip} targeted {count} usernames | Severity: {sev} | Last Attempt: {last_attempt}"
        
    print(msg)
    report_lines.append(msg)

# Optional: save to incident report file
with open("logs/incident_report.txt", "w") as f:
    for line in report_lines:
        f.write(line + "\n")
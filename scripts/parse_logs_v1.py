from collections import defaultdict

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

for ip, count in failed_attempts.items():
    if count >= THRESHOLD:
        print(f"ALERT: Possible brute force attack from IP {ip} ({count} failed attempts)")
    else:
        print(f"INFO: {ip} had {count} failed attempts")
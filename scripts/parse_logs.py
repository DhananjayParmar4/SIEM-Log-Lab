# Simple log parser for suspicious activity

log_file = "logs/sample_logs.txt"  # path to your log file

try:
    with open(log_file, "r") as f:
        logs = f.readlines()
except FileNotFoundError:
    print(f"Error: Log file not found at {log_file}")
    exit(1)

print("Suspicious Events:")
for line in logs:
    if "Failed login" in line:
        print(line.strip())

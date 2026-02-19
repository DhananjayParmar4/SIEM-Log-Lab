import os

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Report files
report_files = [
    "brute_force_report.txt",
    "password_spray_report.txt",
    "web_attack_report.txt"
]

MASTER_REPORT_FILE = os.path.join(LOGS_DIR, "master_incident_report.txt")

with open(MASTER_REPORT_FILE, "w") as master:
    master.write("=== MASTER INCIDENT REPORT ===\n\n")
    
    for file_name in report_files:
        file_path = os.path.join(LOGS_DIR, file_name)
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                master.write(f.read() + "\n")
        else:
            master.write(f"*** WARNING: {file_name} not found ***\n\n")

print(f"Master incident report created at {MASTER_REPORT_FILE}")
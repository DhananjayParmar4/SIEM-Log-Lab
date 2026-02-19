import os
import subprocess

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

# List of scripts to run in order
scripts_to_run = [
    "parse_logs_v1.py",                       # Brute force
    "parse_logs_password_spray_incident.py",  # Password spraying
    "web_attack_detector.py",                 # Web attacks
    "merge_reports.py"                        # Merge all reports
]

for script in scripts_to_run:
    script_path = os.path.join(SCRIPTS_DIR, script)
    print(f"\n--- Running {script} ---")
    subprocess.run(["python3", script_path], check=True)

print("\nAll scripts executed. Master report updated!")
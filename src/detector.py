import re
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "sample.log"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "alerts_report.txt"

IP_FAILURE_THRESHOLD = 3
USER_FAILURE_THRESHOLD = 3
SUSPICIOUS_IPS = {"45.33.32.156", "192.168.1.200"}

failed_ip_attempts = defaultdict(int)
failed_user_attempts = defaultdict(int)
success_after_failure = []
alerts = []


def add_alert(message):
    print(message)
    alerts.append(message)


def analyze_logs():
    print("=== SOC Log Threat Detector ===\n")

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if "Failed password" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for (\w+)', line)

                    if ip_match:
                        ip = ip_match.group(1)
                        failed_ip_attempts[ip] += 1

                        if ip in SUSPICIOUS_IPS:
                            add_alert(f"[HIGH RISK] Login attempt from suspicious IP: {ip}")

                        if failed_ip_attempts[ip] == IP_FAILURE_THRESHOLD:
                            add_alert(f"[ALERT] Possible brute-force attack detected from IP: {ip}")

                    if user_match:
                        user = user_match.group(1)
                        failed_user_attempts[user] += 1

                        if failed_user_attempts[user] == USER_FAILURE_THRESHOLD:
                            add_alert(f"[WARNING] Repeated failed logins detected for user: {user}")

                elif "Accepted password" in line:
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    user_match = re.search(r'for (\w+)', line)

                    if ip_match and user_match:
                        ip = ip_match.group(1)
                        user = user_match.group(1)

                        if failed_ip_attempts[ip] >= IP_FAILURE_THRESHOLD:
                            success_after_failure.append((user, ip))
                            add_alert(
                                f"[CRITICAL] Successful login after repeated failures for user '{user}' from IP: {ip}"
                            )

        generate_summary()
        export_alerts()

    except FileNotFoundError:
        print(f"Error: Could not find log file at: {LOG_FILE}")
    except Exception as error:
        print(f"Unexpected error: {error}")


def generate_summary():
    print("\n=== Summary Report ===")
    print(f"Unique IPs with failed logins: {len(failed_ip_attempts)}")
    print(f"Users targeted: {len(failed_user_attempts)}")

    print("\nFailed login attempts by IP:")
    for ip, count in failed_ip_attempts.items():
        print(f" - {ip}: {count}")

    print("\nFailed login attempts by user:")
    for user, count in failed_user_attempts.items():
        print(f" - {user}: {count}")

    if success_after_failure:
        print("\nSuccessful logins after repeated failures:")
        for user, ip in success_after_failure:
            print(f" - User '{user}' from IP {ip}")
    else:
        print("\nNo successful logins after repeated failures detected.")


def export_alerts():
    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write("SOC Log Threat Detector - Alert Report\n")
        file.write("=" * 45 + "\n\n")

        if alerts:
            for alert in alerts:
                file.write(alert + "\n")
        else:
            file.write("No alerts detected.\n")

    print(f"\nAlert report exported to: {OUTPUT_FILE}")


if __name__ == "__main__":
    analyze_logs()
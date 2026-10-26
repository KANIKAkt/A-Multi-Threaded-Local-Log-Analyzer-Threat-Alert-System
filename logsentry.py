import re
from collections import defaultdict
import argparse

def parse_auth_logs(file_path, threshold=3):
    """
    Parses an authentication log file, extracts IP addresses and failed attempts,
    and flags potential brute-force activities exceeding the threshold.
    """
    failure_pattern = re.compile(
        r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
    )
    
    failed_attempts = defaultdict(list)
    total_parsed = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                total_parsed += 1
                match = failure_pattern.search(line)
                if match:
                    timestamp_str, user, ip_address = match.groups()
                    failed_attempts[ip_address].append({
                        "user": user,
                        "timestamp": timestamp_str
                    })
    except FileNotFoundError:
        print(f"[-] Error: The log file '{file_path}' was not found.")
        return

    print(f"[+] Audit Complete. Parsed {total_parsed} lines.")
    print("-" * 50)
    print(f"{'IP ADDRESS':<18} | {'FAILED COUNT':<12} | {'STATUS'}")
    print("-" * 50)

    for ip, attempts in failed_attempts.items():
        count = len(attempts)
        status = "[!] THREAT DETECTED (Brute-Force Risk)" if count >= threshold else "[i] Normal"
        print(f"{ip:<18} | {count:<12} | {status}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogSentry - Local Log Analyzer & Threat Detector")
    parser.add_argument("--logfile", type=str, default="auth_sample.log", help="Path to the log file")
    parser.add_argument("--threshold", type=int, default=2, help="Failed attempt threshold for threat flagging")
    
    args = parser.parse_args()
    parse_auth_logs(args.logfile, threshold=args.threshold)
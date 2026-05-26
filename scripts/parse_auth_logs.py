#!/usr/bin/env python3
"""
Authentication Log Parser for SOC Triage.
Extracts failed authentication attempts and identifies top offending source IPs.
"""

import re
import sys
import argparse
from collections import Counter

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)"
)

def parse_auth_file(filepath):
    failed_ips = Counter()
    targeted_users = Counter()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = FAILED_PASSWORD_PATTERN.search(line)
            if m:
                user, ip, port = m.groups()
                failed_ips[ip] += 1
                targeted_users[user] += 1
    return failed_ips, targeted_users

def main():
    parser = argparse.ArgumentParser(description="Parse Linux auth.log for brute-force attacks")
    parser.add_argument("logfile", help="Path to auth.log file")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Minimum failures to report (default: 5)")
    args = parser.parse_args()

    try:
        failed_ips, targeted_users = parse_auth_file(args.logfile)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Source IPs exceeding {args.threshold} failed login attempts:")
    flagged = [(ip, count) for ip, count in failed_ips.items() if count >= args.threshold]
    flagged.sort(key=lambda x: x[1], reverse=True)
    for ip, count in flagged:
        print(f"  - {ip}: {count} attempts")

if __name__ == "__main__":
    main()

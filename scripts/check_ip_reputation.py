#!/usr/bin/env python3
"""
IP Reputation lookup helper for SOC analysts.
Queries AbuseIPDB API v2 to enrich source IPs.
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error

def check_ip_reputation(ip_address: str, api_key: str = None):
    """Queries AbuseIPDB API for abuse confidence score."""
    if not api_key:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY environment variable not set"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json"
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.URLError as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Check IP reputation score")
    parser.add_argument("ip", help="IPv4 address to query")
    args = parser.parse_args()

    result = check_ip_reputation(args.ip)
    if "error" in result:
        print(f"[!] {result['error']}", file=sys.stderr)
        sys.exit(1)

    data = result.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    country = data.get("countryCode", "Unknown")
    isp = data.get("isp", "Unknown")
    print(f"[+] IP: {args.ip} | Abuse Score: {score}% | Country: {country} | ISP: {isp}")

if __name__ == "__main__":
    main()

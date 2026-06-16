#!/usr/bin/env python3
"""
Automated IOC Extractor from incident triage reports.
Detects SHA256, MD5, and IPv4 addresses with optional defanging.
"""

import re
import sys
import json
import argparse

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")

def defang(indicator: str) -> str:
    """Defangs IP addresses and domains to prevent accidental clicking."""
    return indicator.replace(".", "[.]")

def is_private_ip(ip: str) -> bool:
    """Returns True if IP belongs to private or loopback ranges."""
    return ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))

def extract_iocs_from_text(text: str, do_defang: bool = False):
    raw_ips = set(IPV4_REGEX.findall(text))
    public_ips = [ip for ip in raw_ips if not is_private_ip(ip)]
    sha256 = sorted(set(SHA256_REGEX.findall(text)))
    md5 = sorted(set(MD5_REGEX.findall(text)))

    if do_defang:
        public_ips = [defang(ip) for ip in public_ips]

    return {
        "ipv4": sorted(public_ips),
        "sha256": sha256,
        "md5": md5
    }

def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from text files")
    parser.add_argument("file", help="Path to report file")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--defang", action="store_true", help="Defang extracted IPs")
    args = parser.parse_args()

    try:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    results = extract_iocs_from_text(content, do_defang=args.defang)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"[+] Extracted IOCs:")
        print(f"  - Public IPs: {len(results['ipv4'])}")
        for ip in results['ipv4']:
            print(f"    {ip}")
        print(f"  - SHA256 hashes: {len(results['sha256'])}")
        for h in results['sha256']:
            print(f"    {h}")

if __name__ == "__main__":
    main()

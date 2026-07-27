#!/usr/bin/env python3
"""
Volatile Memory Malfind Section Analyzer.
Parses memory analysis triage dumps to detect executable VAD blocks lacking disk backing.
"""

import sys
import re
import argparse

def parse_malfind_output(text: str):
    """Extracts process names, PIDs, and vad addresses from Volatility malfind text output."""
    pattern = re.compile(r"Process:\s+(\S+)\s+Pid:\s+(\d+)\s+Address:\s+(0x[a-fA-F0-9]+)")
    injected_processes = []
    for line in text.splitlines():
        m = pattern.search(line)
        if m:
            proc, pid, addr = m.groups()
            injected_processes.append({
                "process": proc,
                "pid": int(pid),
                "address": addr
            })
    return injected_processes

def main():
    parser = argparse.ArgumentParser(description="Parse Volatility malfind outputs")
    parser.add_argument("file", help="Path to malfind text report")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    results = parse_malfind_output(content)
    print(f"[+] Found {len(results)} suspicious unbacked memory sections:")
    for r in results:
        print(f"  - {r['process']} (PID {r['pid']}) at {r['address']}")

if __name__ == "__main__":
    main()

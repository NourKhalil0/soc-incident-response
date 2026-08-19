#!/usr/bin/env python3
"""
DNS and Network Artifact Triage Helper.
Calculates Shannon entropy on queried domain names to identify suspected DGA C2 domains.
"""

import math
import sys
import argparse
from collections import Counter

def calculate_shannon_entropy(domain: str) -> float:
    """Calculates Shannon entropy for the second-level domain name."""
    clean = domain.split(".")[0].lower()
    if not clean:
        return 0.0
    length = len(clean)
    counts = Counter(clean)
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return round(entropy, 3)

def is_suspicious_domain(domain: str, threshold: float = 3.5) -> bool:
    """Returns True if the domain entropy exceeds the given threshold."""
    clean = domain.split(".")[0].lower()
    if len(clean) < 8:
        return False
    return calculate_shannon_entropy(domain) >= threshold

def main():
    parser = argparse.ArgumentParser(description="Analyze domain entropy for DGA detection")
    parser.add_argument("domains", nargs="+", help="Domains to analyze")
    parser.add_argument("-t", "--threshold", type=float, default=3.5, help="Entropy threshold (default: 3.5)")
    args = parser.parse_args()

    for d in args.domains:
        ent = calculate_shannon_entropy(d)
        flag = "[SUSPICIOUS DGA]" if is_suspicious_domain(d, args.threshold) else "[NORMAL]"
        print(f"{flag} {d} (Entropy: {ent})")

if __name__ == "__main__":
    main()

# Enriched threshold verification

#!/usr/bin/env python3
"""
Windows Security Event XML Log Parser for SOC Triage.
Filters exported Windows Event XML records for critical security Event IDs.
"""

import sys
import argparse
import xml.etree.ElementTree as ET
from collections import Counter

CRITICAL_EVENT_IDS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4688": "Process Creation",
    "4698": "Scheduled Task Created",
    "4720": "User Account Created",
    "7045": "Service Installed",
    "1102": "Audit Log Cleared"
}

def parse_events_xml(xml_content: str):
    """Parses an XML string containing one or more <Event> elements."""
    events = []
    xml_content = xml_content.strip()
    if not xml_content.startswith("<Events>"):
        xml_content = f"<Events>{xml_content}</Events>"

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}", file=sys.stderr)
        return []

    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    # Search with and without namespace
    elements = root.findall(".//Event")
    if not elements:
        elements = root.findall(".//ns:Event", ns)

    for event in elements:
        sys_elem = event.find("System")
        if sys_elem is None:
            sys_elem = event.find("ns:System", ns)
        if sys_elem is None:
            continue

        eid_elem = sys_elem.find("EventID")
        if eid_elem is None:
            eid_elem = sys_elem.find("ns:EventID", ns)

        eid = eid_elem.text.strip() if (eid_elem is not None and eid_elem.text) else "Unknown"

        time_elem = sys_elem.find("TimeCreated")
        if time_elem is None:
            time_elem = sys_elem.find("ns:TimeCreated", ns)

        timestamp = time_elem.get("SystemTime", "Unknown") if time_elem is not None else "Unknown"

        events.append({
            "event_id": eid,
            "description": CRITICAL_EVENT_IDS.get(eid, "Other Event"),
            "timestamp": timestamp
        })
    return events

def summarize_events(events):
    counts = Counter(e["event_id"] for e in events)
    return {eid: (counts[eid], CRITICAL_EVENT_IDS.get(eid, "Other")) for eid in counts}

def main():
    parser = argparse.ArgumentParser(description="Parse Windows Security XML events")
    parser.add_argument("file", help="Path to XML event export")
    parser.add_argument("-f", "--filter", help="Filter by specific Event ID")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    events = parse_events_xml(content)
    if args.filter:
        events = [e for e in events if e["event_id"] == args.filter]

    print(f"Parsed {len(events)} events.")
    summary = summarize_events(events)
    for eid, (cnt, desc) in summary.items():
        print(f"  Event ID {eid} ({desc}): {cnt}")

if __name__ == "__main__":
    main()

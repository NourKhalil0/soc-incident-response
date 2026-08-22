# Playbook 07: Ransomware Root Cause Analysis & Forensic Post-Mortem

## 1. Objective
Determine exact patient-zero workstation, initial compromise vector, and dwell time following a ransomware incident.

## 2. Key Forensic Artifacts
- **Master File Table ($MFT):** Identify timestamps of initial dropper staging.
- **USN Journal:** Pinpoint mass file renaming and ransom note dropping sequence.
- **Shimcache / Amcache:** Verify execution evidence for uninstalled attacker utilities.

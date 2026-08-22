# Playbook 07: Ransomware Root Cause Analysis & Forensic Post-Mortem

## 1. Objective
Determine exact patient-zero workstation, initial compromise vector, and dwell time following a ransomware incident.

## 2. Key Forensic Artifacts
- **Master File Table ($MFT):** Identify timestamps of initial dropper staging.
- **USN Journal:** Pinpoint mass file renaming and ransom note dropping sequence.
- **Shimcache / Amcache:** Verify execution evidence for uninstalled attacker utilities.

## 3. Timeline Reconstruction Sequence
1. Extract MFT using FTK Imager.
2. Parse MFT records using `analyzeMFT.py`.
3. Plot created timestamps against first observed network C2 beacon.

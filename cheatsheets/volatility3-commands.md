# Volatility 3 Memory Forensics Cheatsheet

Command reference for triage of memory dumps (`.raw`, `.vmem`, `.dmp`).

## 1. Process Hierarchy & Anomaly Detection
```bash
# List running processes and thread counts
python3 vol.py -f memory.raw windows.pslist

# Visualize process tree to identify parent-child anomalies
python3 vol.py -f memory.raw windows.pstree

# Scan for unlinked or hidden EPROCESS blocks
python3 vol.py -f memory.raw windows.psscan
```

## 2. Injected Code & Hollowed Binaries
```bash
# Scan for executable VAD segments not backed by disk image
python3 vol.py -f memory.raw windows.malfind
```

## 3. Network Sockets
```bash
# Enumerate active and closed TCP/UDP connections
python3 vol.py -f memory.raw windows.netscan
```

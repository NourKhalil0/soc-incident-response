# Volatility 3 Memory Forensics Cheatsheet

Command reference for triage of memory dumps (`.raw`, `.vmem`, `.dmp`).

## 1. Process Hierarchy & Anomaly Detection
`python3 vol.py -f memory.raw windows.pslist`
`python3 vol.py -f memory.raw windows.pstree`
`python3 vol.py -f memory.raw windows.psscan`

## 2. Injected Code
`python3 vol.py -f memory.raw windows.malfind`

## 3. Network Sockets in Volatile Memory
`python3 vol.py -f memory.raw windows.netscan`

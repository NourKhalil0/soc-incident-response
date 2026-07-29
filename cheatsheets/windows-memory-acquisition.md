# Windows Memory Acquisition Guide

Procedures for collecting volatile RAM artifacts during live triage.

## Tools
- **WinPmem:** `winpmem.exe -o mem_dump.raw`
- **DumpIt:** Native x64 memory dumper
- **FTK Imager Lite:** CLI capture

## Hash Verification
Compute SHA-256 immediately after acquisition:
`certutil -hashfile mem_dump.raw SHA256 > mem_dump.sha256`

## Linux / ESXi Volatile Capture
- LiME (Linux Memory Extractor): `insmod lime.ko "path=/tmp/ram.lime format=raw"`

- Verify kernel header compatibility prior to loading LiME.

## Volatility 3 Analysis Commands
`python3 vol.py -f mem.raw windows.malfind`
`python3 vol.py -f mem.raw windows.psscan`

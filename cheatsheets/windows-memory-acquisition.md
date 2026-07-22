# Windows Memory Acquisition Guide

Procedures for collecting volatile RAM artifacts during live triage.

## Tools
- **WinPmem:** `winpmem.exe -o mem_dump.raw`
- **DumpIt:** Native x64 memory dumper
- **FTK Imager Lite:** CLI capture

## Hash Verification
Compute SHA-256 immediately after acquisition:
`certutil -hashfile mem_dump.raw SHA256 > mem_dump.sha256`

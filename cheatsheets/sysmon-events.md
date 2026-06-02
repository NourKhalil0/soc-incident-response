# Sysmon Critical Event IDs Reference

Windows System Monitor (Sysmon) provides detailed endpoint logging.

| Event ID | Name | Detection Value |
|---|---|---|
| Event ID 1 | Process Creation | Parent-child relationship, command-line arguments, hashes |
| Event ID 3 | Network Connection | Outbound C2 connections, beaconing, lateral movement |
| Event ID 7 | Image Loaded | DLL injection, unsigned DLL loading |
| Event ID 8 | CreateRemoteThread | Process injection (e.g. Cobalt Strike, shellcode runners) |
| Event ID 10 | ProcessAccess | LSASS memory access (`0x1010` / `0x1FFFFF` by Mimikatz) |
| Event ID 11 | FileCreate | Dropper payload staging in AppData / Temp |
| Event ID 12/13 | Registry Event | Persistence mechanisms in `Run` and `RunOnce` keys |
| Event ID 22 | DNSEvent | DNS tunneling, DGA domains, C2 domain resolution |

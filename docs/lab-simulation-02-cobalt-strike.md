# Lab Simulation 02: Cobalt Strike Beacon Triage

## 1. Scenario
Emulated adversary executed PowerShell download cradle and spawned HTTPS beacon on victim workstation.

## 2. Telemetry Timeline
- 09:12:04: Event ID 4688: powershell.exe with WebClient cradle.
- 09:12:15: Event ID 7: Sysmon image load for unbacked DLL.
- 09:12:30: Network connection established to C2 over TCP 443.

## 3. Mitigation & Detection Validation
- Sigma rule `proc_creation_win_powershell_download_cradle.yml` triggered within 4 seconds.
- Host quarantined via Defender EDR.

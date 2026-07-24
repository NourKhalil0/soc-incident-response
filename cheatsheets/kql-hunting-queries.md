# Microsoft Sentinel / Defender XDR KQL Cheatsheet

## 1. Suspicious Process Launched from Temp / AppData
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

## 2. Suspicious Outbound Connections by Unsigned Binaries
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (4444, 8080, 8443, 9001, 1337)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

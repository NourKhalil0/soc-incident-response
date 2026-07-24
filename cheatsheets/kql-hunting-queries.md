# Microsoft Sentinel / Defender XDR KQL Cheatsheet

## 1. Suspicious Process Launched from Temp / AppData
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

# Microsoft Sentinel / Defender XDR KQL Cheatsheet

## 1. Suspicious Process Launched from Temp / AppData
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\AppData\\Local\\Temp\\", "\\Users\\Public\\")
| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## 2. High Volume Failed Sign-ins (Password Spray)
```kql
SigninLogs
| where CreatedDateTime > ago(1d)
| where ResultType in ("50126", "50053")
| summarize FailureCount = count(), UniqueAccounts = dcount(UserPrincipalName) by IPAddress
| where UniqueAccounts >= 10
```

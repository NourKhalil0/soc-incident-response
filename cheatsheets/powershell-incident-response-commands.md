# Live Incident Response PowerShell Cheatsheet

Rapid live triage commands for Windows endpoints.

## 1. Active Connections & Listening Ports
`Get-NetTCPConnection | Where-Object State -eq 'Established' | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess`

## 2. Process Lineage & Command Lines
`Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine`

## 3. Local Account & Administrators
`Get-LocalGroupMember -Group 'Administrators'`

## 4. Scheduled Tasks
`Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName, TaskPath`

## 5. Persistence in Registry
`Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'`

- Note: Always pipe output to hash tables or out-file for chain of custody.

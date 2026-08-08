# Live Incident Response PowerShell Cheatsheet

Rapid live triage commands for Windows endpoints.

## 1. Active Connections & Listening Ports
`Get-NetTCPConnection | Where-Object State -eq 'Established' | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess`

## 2. Process Lineage & Command Lines
`Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine`

## 3. Local Account & Administrators
`Get-LocalGroupMember -Group 'Administrators'`

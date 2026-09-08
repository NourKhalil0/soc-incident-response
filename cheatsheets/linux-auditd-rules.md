# Linux Auditd Rules Reference

Rules for `/etc/audit/rules.d/audit.rules`.

## 1. Monitor Execution of Privileged Binaries
```text
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged_cmd
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged_cmd
```

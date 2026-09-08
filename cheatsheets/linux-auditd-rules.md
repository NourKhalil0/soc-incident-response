# Linux Auditd Rules Reference

Rules for `/etc/audit/rules.d/audit.rules`.

## 1. Monitor Execution of Privileged Binaries
```text
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged_cmd
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged_cmd
```

## 2. Monitor Sensitive Identity Files
```text
-w /etc/shadow -p wa -k identity_tampering
-w /etc/passwd -p wa -k identity_tampering
-w /etc/sudoers -p wa -k sudoers_tampering
```

## 3. Monitor Kernel Module Operations
```text
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k module_manipulation
```

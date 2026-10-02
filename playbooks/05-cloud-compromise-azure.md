# Playbook 05: Azure & Entra ID Cloud Incident Response

## 1. Scope & Objective
Provide standardized procedures for incident responders to triage, contain, and remediate compromised cloud identities, rogue OAuth application grants, and unauthorized data access in Microsoft Azure and Entra ID environments.

## 2. Trigger Conditions
- High-severity alerts from Microsoft Defender for Cloud / Entra ID Protection:
  - *Atypical travel* or *Unfamiliar sign-in properties* for privileged accounts.
  - *Anomalous token usage* (session cookie replay or Primary Refresh Token theft).
  - *Suspicious granting of high-privilege application permissions* (`Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`).
- Perimeter firewall or CASB alert indicating mass data download via `AzCopy` or Storage Explorer.

## 3. Initial Triage & Evidence Preservation

### 3.1 Investigate Sign-in Telemetry
Query Entra ID Sign-in Logs using Microsoft Graph PowerShell or Sentinel KQL:
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "compromised.user@domain.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ClientAppUsed, ConditionalAccessStatus, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

### 3.2 Audit Directory Role & Credential Modifications
Check for newly added authentication credentials, MFA tampering, or elevated role assignments:
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add service principal credentials", "Add user", "Update user")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, Target, InitiatedBy, Result
```

## 4. Immediate Containment Sequence

Execute rapid containment actions via Microsoft Graph PowerShell SDK:

```powershell
# Connect to Microsoft Graph with required administrative scopes
Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.AccessAsUser.All"

$TargetUser = "compromised.user@domain.com"

# 1. Invalidate all active refresh tokens and browser sessions immediately
Revoke-MgUserSignInSession -UserId $TargetUser

# 2. Disable user account to prevent re-authentication
Update-MgUser -UserId $TargetUser -AccountEnabled $false

# 3. List and review registered authentication methods for unauthorized FIDO2 / Authenticator apps
Get-MgUserAuthenticationMethod -UserId $TargetUser
```

## 5. Storage & Exfiltration Remediation
If storage account access keys or SAS tokens were compromised:
1. Regenerate Storage Account access keys (`Key1` and `Key2`) using Azure CLI:
   ```bash
   az storage account keys renew --account-name <storage_account> --resource-group <resource_group> --key primary
   ```
2. Revoke active Shared Access Signatures (SAS) by updating stored access policies or regenerating delegation keys.
3. Review Azure Storage diagnostic logs for anomalous `GetBlob` operations.

## 6. Post-Incident & Lessons Learned
- [ ] Enforce Continuous Access Evaluation (CAE) on all Conditional Access policies.
- [ ] Implement FIDO2 / Certificate-Based Authentication for all Global and Privileged Role administrators.
- [ ] Map all observed indicators of compromise (IOCs) into organizational SIEM and threat intelligence feeds.

---
*Reference Standards: NIST SP 800-61 Rev. 2, CISA Cloud Security Technical Reference Architecture.*

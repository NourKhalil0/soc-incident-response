# Playbook 03: Compromised Credentials & Account Takeover

## 1. Scope & Triggers
Applicable when user accounts trigger impossible travel alerts, anomalous MFA prompts, or leaked credential breach notices.

## 2. Containment Sequence
1. **Revoke Active Refresh Tokens:**
   ```powershell
   Revoke-MgUserSignInSession -UserId <UserPrincipalName>
   ```
2. **Force Password Reset:** Invalidate cached Kerberos tickets (`klist purge`).
3. **Audit Registered Authentication Methods:** Check for newly added rogue FIDO2 keys or Authenticator apps.
4. **Review Email Inbox Forwarding Rules:** Attackers frequently add auto-forwarding rules:
   ```powershell
   Get-InboxRule -Mailbox <UserPrincipalName> | Select-Object Name, Description, ForwardTo
   ```

# Playbook 03: Compromised Credentials & Account Takeover

## 1. Scope & Triggers
Applicable when user accounts trigger impossible travel alerts or leaked credential breach notices.

## 2. Containment Sequence
1. Invalidate active session tokens (`Revoke-MgUserSignInSession`).
2. Force password reset and audit registered MFA methods.

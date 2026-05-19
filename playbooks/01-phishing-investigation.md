# Playbook 01: Phishing Email Investigation

## 1. Scope & Objective
Guide Tier 1 and Tier 2 SOC analysts through triage, header analysis, attachment verification, and mailbox containment of reported suspicious emails.

## 2. Initial Triage Checklist
- [ ] Export raw email in `.eml` or `.msg` format.
- [ ] Inspect originating IP and client hostname from earliest `Received:` header.
- [ ] Verify SPF, DKIM, and DMARC authentication verdicts in `Authentication-Results`.
- [ ] Check sender domain for typosquatting / visual lookalike characters.

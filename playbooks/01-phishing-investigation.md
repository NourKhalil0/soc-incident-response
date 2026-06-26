# Playbook 01: Phishing Email Investigation

## 1. Scope & Objective
Guide Tier 1 and Tier 2 SOC analysts through triage, header analysis, attachment verification, and mailbox containment of reported suspicious emails.

## 2. Initial Triage Checklist
- [ ] Export raw email in `.eml` or `.msg` format.
- [ ] Inspect originating IP and client hostname from earliest `Received:` header.
- [ ] Verify SPF, DKIM, and DMARC authentication verdicts in `Authentication-Results`.
- [ ] Check sender domain for typosquatting / visual lookalike characters.

## 3. Header Analysis Procedures
1. **SPF (Sender Policy Framework):** Check if sending server IP is authorized in sender domain TXT DNS record.
2. **DKIM (DomainKeys Identified Mail):** Validate cryptographic signature against published public key.
3. **DMARC (Domain-based Message Authentication):** Check alignment between visible `From:` header and authenticated SPF/DKIM domains.

## 4. Attachment & URL Analysis
- Compute SHA-256 hash before opening any file.
- Submit samples to automated sandbox (ANY.RUN, Hybrid Analysis, CAPEv2).
- Inspect extracted macro streams using `olevba`.
- Defang all extracted URLs before documenting in incident tickets.

## 5. Mailbox Containment Procedures
- Use Microsoft Defender for Office 365 Explorer to execute a tenant-wide `HardDelete`.
- Block sender domain and originating IP on perimeter secure email gateway (SEG).

# Playbook 06: Insider Threat & Data Exfiltration

## 1. Trigger Criteria
- Mass file download from SharePoint / OneDrive by departing employee.
- USB Mass Storage device inserted on sensitive workstation.
- Sensitive data transferred via personal webmail or cloud storage.

## 2. USB Artifact Triage
- Inspect registry key `SYSTEM\CurrentControlSet\Enum\USBSTOR`.
- Review `setupapi.dev.log` for device serial number and first connection timestamp.

## 3. Cloud Storage Audit
- Review Microsoft Purview Audit log for `FileDownloaded` events.
- Correlate volume of downloaded files with user's historical 30-day baseline.

## 4. Immediate Containment
- Block external USB write access via Intune Device Control.
- Revoke user session and apply restrictive Conditional Access policy.

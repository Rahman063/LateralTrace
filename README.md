# LateralTrace

### Windows Lateral Movement Investigation Lab

LateralTrace is a Python/Flask-based SIEM-style security monitoring and investigation platform designed to detect, correlate, and investigate Windows lateral movement activity.

It ingests Windows Security Event Logs, stores normalized security events in SQLite, applies detection and correlation logic, generates risk-based alerts, and provides an investigation workflow for security analysts.

---

## Features

- Windows Security Event Log collection
- Support for Windows security events including:
  - Event ID 4624 - Successful Logon
  - Event ID 4625 - Failed Logon
  - Event ID 4634 - Logoff
  - Event ID 4648 - Explicit Credential Usage
  - Event ID 4672 - Special Privileges Assigned
  - Event ID 4688 - Process Creation
- SQLite-based event storage
- Synthetic Windows security event generation for lab testing
- Real Windows event ingestion
- Detection of:
  - Remote logons
  - Failed logons
  - Privileged logons
  - Explicit credential usage
  - Suspicious process execution
- Account and host investigation
- Event search and filtering
- Investigation timelines
- Lateral movement correlation
- Risk scoring
- Security alert management
- Incident investigation workflow
- MITRE ATT&CK technique mapping
- Attack graph visualization
- Security incident report generation
- Continuous Windows event monitoring

---

## Architecture

```text
Windows Security Events
          |
          v
   Event Collector
          |
          v
   Event Normalization
          |
          v
       SQLite
          |
          v
    Detection Engine
          |
          v
   Correlation Engine
          |
          v
      Risk Scoring
          |
          v
        Alerts
          |
          v
 Incident Investigation
     |       |       |
     v       v       v
 Timeline   Graph   MITRE ATT&CK
          |
          v
    Security Report

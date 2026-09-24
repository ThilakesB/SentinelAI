# User Stories Document
## CyberGuard AI — On-Device Threat Detection Platform

**Version:** 1.0  
**Date:** September 2026  
**Format:** As a [user type], I want [goal], so that [benefit].

---

## 1. Epic Overview

| Epic | ID | Description |
|---|---|---|
| Process Monitoring | E-01 | Real-time AI-powered process scanning and threat classification |
| Threat Response | E-02 | Detecting and eliminating threats via automated or supervised actions |
| Network Analysis | E-03 | Network log ingestion and anomaly detection |
| Dashboard | E-04 | Centralized monitoring, alerting, and management UI |
| Multi-Device | E-05 | Monitoring and managing multiple machines from one place |
| Configuration | E-06 | Customizing behavior via settings, whitelists, thresholds |
| Security & Access | E-07 | Authentication, authorization, and audit logging |
| Resource Prediction | E-08 | Predicting and alerting on resource anomalies proactively |

---

## 2. User Stories by Epic

---

### Epic E-01: Process Monitoring

**US-001** *(Priority: P0)*  
**As a** System Administrator,  
**I want** CyberGuard AI to continuously scan all running processes on my server,  
**So that** I always have a real-time view of what's consuming my system's resources.

**Acceptance Criteria:**
- [ ] All processes are listed with PID, name, CPU%, RAM usage, and network I/O
- [ ] Process list refreshes every 5 seconds (configurable)
- [ ] List is visible in real-time on the dashboard without manual refresh

---

**US-002** *(Priority: P0)*  
**As a** Security Engineer,  
**I want** each process to be assigned an AI-generated threat score (0.0–1.0),  
**So that** I can quickly identify which processes are suspicious without manually analyzing logs.

**Acceptance Criteria:**
- [ ] Every process in the table has a visible threat score
- [ ] Scores are color-coded: green (SAFE), yellow (SUSPICIOUS), red (MALICIOUS)
- [ ] AI scoring completes within 50ms per scan cycle
- [ ] Clicking on a process shows detailed reasoning for the score

---

**US-003** *(Priority: P1)*  
**As a** System Administrator,  
**I want** to whitelist known-good processes,  
**So that** legitimate tools like database engines or backup agents don't trigger false alerts.

**Acceptance Criteria:**
- [ ] Admin can whitelist by process name, executable path, or SHA-256 hash
- [ ] Whitelisted processes show a "Trusted" badge and are excluded from AI scoring
- [ ] Whitelist entries can be removed at any time
- [ ] Whitelist changes are recorded in the audit log

---

**US-004** *(Priority: P1)*  
**As a** IT Manager,  
**I want** to see historical process data and threat scores,  
**So that** I can investigate what was happening on the server at a specific time.

**Acceptance Criteria:**
- [ ] Process history is stored for at least 30 days
- [ ] Admin can filter history by device, time range, and threat level
- [ ] History view shows a timeline of threat score changes per process

---

### Epic E-02: Threat Response

**US-005** *(Priority: P0)*  
**As a** Security Engineer,  
**I want** to kill a suspicious process directly from the dashboard with a single click,  
**So that** I can respond to threats immediately without logging into the server via SSH.

**Acceptance Criteria:**
- [ ] Kill button is visible for all SUSPICIOUS and MALICIOUS processes
- [ ] Clicking Kill triggers a confirmation dialog with process details
- [ ] Upon confirmation, the process is terminated within 1 second
- [ ] Kill action is recorded in the audit log

---

**US-006** *(Priority: P1)*  
**As a** System Administrator without 24/7 monitoring,  
**I want** CyberGuard AI to automatically kill MALICIOUS processes (score ≥ 0.85) without my intervention,  
**So that** threats are neutralized even when I'm not at my desk.

**Acceptance Criteria:**
- [ ] Autonomous Kill Mode can be enabled per device in settings
- [ ] Only processes with score ≥ 0.85 are auto-killed (configurable threshold)
- [ ] System-critical PIDs (PID 1, kernel processes) are never auto-killed
- [ ] Auto-kill is followed by an immediate push notification/email alert
- [ ] All auto-kills are recorded in the audit log

---

**US-007** *(Priority: P0)*  
**As a** Compliance Officer,  
**I want** a complete, tamper-proof record of every process kill action,  
**So that** I can demonstrate due diligence during security audits.

**Acceptance Criteria:**
- [ ] Every kill action has: timestamp, device, PID, process name, threat score, action mode, user or "system"
- [ ] Audit log uses hash chaining to prevent tampering
- [ ] Log is exportable as CSV or JSON
- [ ] Log is searchable and filterable by date range, device, severity

---

**US-008** *(Priority: P2)*  
**As a** Security Engineer,  
**I want** CyberGuard AI to quarantine a suspicious process rather than immediately killing it,  
**So that** I can analyze it in an isolated environment before deciding to terminate.

**Acceptance Criteria:**
- [ ] Quarantine mode suspends process execution without killing it
- [ ] Quarantined processes are listed separately in the dashboard
- [ ] Admin can release (resume) or kill quarantined processes
- [ ] Quarantine state is logged in the audit trail

---

### Epic E-03: Network Analysis

**US-009** *(Priority: P0)*  
**As a** Security Engineer,  
**I want** CyberGuard AI to monitor network logs for suspicious connection patterns,  
**So that** I can detect C2 beaconing, DNS tunneling, and data exfiltration.

**Acceptance Criteria:**
- [ ] Agent ingests syslog, journald, and/or Windows Event Log
- [ ] Detects: C2 beaconing, DNS tunneling, port scanning, large outbound transfers
- [ ] Flagged network events appear as alerts in the dashboard
- [ ] Network alert includes: source IP/process, destination IP/domain, anomaly type, time

---

**US-010** *(Priority: P1)*  
**As a** IT Administrator,  
**I want** to see which processes are making network connections and to where,  
**So that** I can spot unauthorized outbound connections from my server.

**Acceptance Criteria:**
- [ ] Per-process network connection list shows: remote IP, port, protocol, bytes sent/received
- [ ] IP addresses are resolved to hostnames when possible
- [ ] Known malicious IPs from the local threat intelligence database are flagged
- [ ] Connection data updates in real-time

---

**US-011** *(Priority: P1)*  
**As a** Security Engineer,  
**I want** network threat intelligence checks to work fully offline,  
**So that** the tool remains effective on air-gapped or restricted networks.

**Acceptance Criteria:**
- [ ] Threat intelligence database is bundled locally and updated offline
- [ ] No DNS or HTTP calls to external IPs during scanning (unless cloud sync is enabled)
- [ ] Local database covers top 10,000 known malicious IPs and domains

---

### Epic E-04: Dashboard

**US-012** *(Priority: P0)*  
**As a** System Administrator,  
**I want** a web dashboard that shows all my monitored devices and their current threat status at a glance,  
**So that** I can immediately see if any machine requires attention.

**Acceptance Criteria:**
- [ ] Dashboard home shows all connected devices with colored status indicators
- [ ] CRITICAL alerts are shown prominently without scrolling on a 1080p display
- [ ] Dashboard loads in under 2 seconds
- [ ] Data refreshes in real-time via WebSocket

---

**US-013** *(Priority: P0)*  
**As a** Security Engineer,  
**I want** to receive alert notifications when a new CRITICAL or HIGH threat is detected,  
**So that** I don't have to keep the dashboard open to be notified.

**Acceptance Criteria:**
- [ ] Browser push notifications for CRITICAL alerts
- [ ] Optional email notifications for alerts above a configurable severity threshold
- [ ] Notification includes: device name, process name, threat score, recommended action

---

**US-014** *(Priority: P1)*  
**As a** IT Manager,  
**I want** summary charts showing threat trends over time,  
**So that** I can report on the security posture of our infrastructure to leadership.

**Acceptance Criteria:**
- [ ] Dashboard shows: number of threats detected this week, kill actions taken, top threat types
- [ ] Charts are filterable by time range (last 24h, 7d, 30d)
- [ ] Report can be exported as PDF

---

### Epic E-05: Multi-Device Monitoring

**US-015** *(Priority: P1)*  
**As a** System Administrator managing 10+ servers,  
**I want** to monitor all servers from a single dashboard,  
**So that** I don't have to log into each server individually.

**Acceptance Criteria:**
- [ ] Dashboard supports at least 50 devices simultaneously
- [ ] Each device shows: hostname, OS, agent version, last heartbeat, current threat level
- [ ] Devices can be organized into groups (e.g., by environment: production, staging)
- [ ] Clicking a device shows its detailed process table and alerts

---

**US-016** *(Priority: P1)*  
**As a** Security Engineer,  
**I want** to see if a threat is affecting multiple machines simultaneously,  
**So that** I can identify coordinated attacks or lateral movement.

**Acceptance Criteria:**
- [ ] Cross-device alert correlation shows when the same process name or IP appears on multiple machines
- [ ] Correlated alerts are flagged with a "Multi-device" indicator

---

### Epic E-06: Configuration

**US-017** *(Priority: P0)*  
**As a** System Administrator,  
**I want** to configure the scan interval and threat score thresholds,  
**So that** I can tune the tool to my organization's risk tolerance and performance requirements.

**Acceptance Criteria:**
- [ ] Scan interval is configurable (1–60 seconds)
- [ ] Threat score thresholds for SUSPICIOUS and MALICIOUS are configurable
- [ ] Autonomous kill threshold is configurable (0.7–1.0)
- [ ] Configuration changes are logged in the audit trail

---

**US-018** *(Priority: P1)*  
**As a** IT Administrator,  
**I want** to configure which log sources the agent reads,  
**So that** I can adapt the tool to our specific server setup and logging configuration.

**Acceptance Criteria:**
- [ ] Agent config file accepts custom syslog paths
- [ ] Support for multiple concurrent log sources
- [ ] Log source parsing errors are reported in the dashboard

---

### Epic E-07: Security & Access

**US-019** *(Priority: P0)*  
**As a** IT Manager,  
**I want** the dashboard to require authentication,  
**So that** only authorized personnel can access threat data and perform kill actions.

**Acceptance Criteria:**
- [ ] Dashboard requires username and password to access
- [ ] Passwords are stored as bcrypt hashes
- [ ] Sessions expire after 8 hours of inactivity
- [ ] Failed login attempts are rate-limited after 5 attempts

---

**US-020** *(Priority: P1)*  
**As a** Security Engineer,  
**I want** MFA (Multi-Factor Authentication) for dashboard login,  
**So that** even if my password is compromised, my dashboard access is protected.

**Acceptance Criteria:**
- [ ] MFA via TOTP (Google Authenticator compatible)
- [ ] MFA enrollment via QR code in account settings
- [ ] MFA can be enforced as mandatory for all users by admin

---

### Epic E-08: Resource Prediction

**US-021** *(Priority: P1)*  
**As a** System Administrator,  
**I want** CyberGuard AI to predict abnormal resource usage spikes before they happen,  
**So that** I can investigate proactively rather than reactively.

**Acceptance Criteria:**
- [ ] System establishes a 7-day behavioral baseline per machine
- [ ] Anomaly prediction alerts fire when current metrics deviate > 2 standard deviations from baseline
- [ ] Predictions include: metric type, predicted peak value, estimated time to peak
- [ ] Predictions can be dismissed or suppressed for known maintenance windows

---

*End of User Stories Document v1.0*

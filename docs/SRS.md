# Software Requirements Specification (SRS)
## CyberGuard AI — On-Device Threat Detection Platform

**Version:** 1.0  
**Date:** September 2026  
**Status:** Draft  
**Standard:** IEEE 830-1998 (adapted)

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification (SRS) document describes the complete functional and non-functional requirements for CyberGuard AI. It is intended for developers, QA engineers, architects, and project stakeholders.

### 1.2 Scope

CyberGuard AI consists of three primary software components:

1. **Monitoring Agent** — A lightweight daemon/service running on monitored machines, responsible for collecting telemetry and executing the on-device AI threat engine.
2. **Central Dashboard** — A web-based UI for administrators to view threat alerts, manage devices, and configure policies.
3. **API Server** — REST + WebSocket server connecting agents to the dashboard.

### 1.3 Definitions

| Term | Definition |
|---|---|
| **Agent** | The background process running on a monitored machine |
| **Threat Score** | A floating-point value (0.0–1.0) indicating how suspicious a process is |
| **Process Elimination** | Forcibly terminating a process via OS kill signal |
| **Baseline Period** | Initial 7-day learning phase to establish normal behavior |
| **MTTD** | Mean Time to Detect — average time from threat appearance to detection |
| **MTTR** | Mean Time to Respond — average time from detection to threat neutralization |
| **C2** | Command-and-Control — server used by attackers to communicate with malware |
| **IOC** | Indicator of Compromise — artifact observed on a network indicating intrusion |

### 1.4 References

- CyberGuard AI PRD v1.0
- OWASP Top 10 Security Risks
- MITRE ATT&CK Framework
- IEEE 830-1998 Standard

---

## 2. Overall Description

### 2.1 Product Perspective

CyberGuard AI operates as a standalone system deployable on any organization's infrastructure. It does not require internet connectivity for core threat detection. An optional cloud channel can be enabled for threat intelligence sharing.

```
┌──────────────────────────────────────────────────────────┐
│                    Organization Network                   │
│                                                          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   │
│  │  Server A   │   │  Server B   │   │  Server C   │   │
│  │  [Agent]    │   │  [Agent]    │   │  [Agent]    │   │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   │
│         │                 │                 │            │
│         └─────────────────┴─────────────────┘            │
│                           │                              │
│                    ┌──────▼──────┐                       │
│                    │  API Server │                       │
│                    └──────┬──────┘                       │
│                           │                              │
│                    ┌──────▼──────┐                       │
│                    │  Dashboard  │                       │
│                    │  (Browser)  │                       │
│                    └─────────────┘                       │
│                                                          │
│  ─ ─ ─ ─ ─ ─ ─ Optional Cloud Sync ─ ─ ─ ─ ─ ─ ─ ─ ─  │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Product Functions (Summary)

- Real-time process scanning and AI-based threat classification
- Network log ingestion and anomaly detection
- Automated and supervised process termination
- Multi-device centralized monitoring dashboard
- Resource usage prediction and alerting
- Comprehensive audit logging

### 2.3 User Classes

| Class | Technical Level | Access Level |
|---|---|---|
| Super Administrator | High | Full system access |
| Security Analyst | High | Read + Response actions |
| IT Administrator | Medium | Monitor + Manage devices |
| Read-Only Viewer | Low | View dashboards only |

### 2.4 Operating Environment

| Component | Supported Environment |
|---|---|
| Agent | Ubuntu 20.04+, Debian 11+, RHEL 8+, Windows Server 2019+, macOS 12+ |
| API Server | Ubuntu 20.04+ / Docker container |
| Dashboard | Chrome 100+, Firefox 100+, Edge 100+, Safari 15+ |
| Database | SQLite (single node), PostgreSQL 14+ (multi-node) |

---

## 3. Functional Requirements

### 3.1 Agent — Process Monitoring Module

#### FR-001: Process Discovery
- The agent SHALL enumerate all running processes on the host OS every **5 seconds** (configurable: 1–60s)
- For each process, the agent SHALL collect: PID, process name, parent PID, CPU%, RAM (MB), disk I/O (MB/s), network bytes sent/received, open file handles, open network ports, process start time, executable path, digital signature status

#### FR-002: AI Threat Classification
- The agent SHALL run each process telemetry record through the embedded ONNX AI model
- The model SHALL output a threat score between 0.0 (safe) and 1.0 (malicious)
- Threat classification thresholds:
  - `0.0 – 0.3`: SAFE
  - `0.3 – 0.7`: SUSPICIOUS (alert, no auto-kill)
  - `0.7 – 1.0`: MALICIOUS (alert + optional auto-kill)
- Inference SHALL complete within **50ms** per process batch

#### FR-003: Anomaly Detection via Heuristics
- In addition to AI scoring, the agent SHALL apply rule-based heuristics:
  - CPU usage > 90% sustained for > 60 seconds by a non-whitelisted process
  - RAM usage > 80% of total system RAM by a single process
  - Network egress > 100MB/min by a process that is not a known update service
  - Process attempting to access `/etc/shadow`, `SAM`, or credential stores
  - Process spawning > 50 child processes within 10 seconds

#### FR-004: Whitelist Management
- Administrators SHALL be able to whitelist processes by: name, executable path hash (SHA-256), digital signature issuer
- Whitelisted processes are excluded from all threat analysis and kill actions

### 3.2 Agent — Network Log Analysis Module

#### FR-005: Log Ingestion
- The agent SHALL ingest the following log sources:
  - Linux: `/var/log/syslog`, `/var/log/auth.log`, `journald`, Zeek/Bro connection logs
  - Windows: Windows Event Log (Security, System, Application channels), WFP logs
  - macOS: Unified Logging System (ULS), `pf` firewall logs

#### FR-006: Network Anomaly Detection
- The agent SHALL detect the following network threats:
  - **DNS Tunneling:** Unusually long DNS query strings (> 50 chars) or high query frequency (> 100/min) to a single domain
  - **C2 Beaconing:** Regular outbound connections at fixed intervals (e.g., every 60 seconds) to non-whitelisted IPs
  - **Port Scanning:** Inbound connection attempts to > 50 different ports within 30 seconds
  - **Data Exfiltration:** Outbound data transfer > 1GB within 1 hour to external IPs
  - **Suspicious TOR/Proxy Usage:** Connections to known TOR exit nodes or proxy services

#### FR-007: Local Threat Intelligence Database
- The agent SHALL maintain a local SQLite database of known malicious IPs, domains, and file hashes
- The database SHALL be updated from a bundled signature pack during installation
- Optional: online update when cloud sync is enabled

### 3.3 Agent — Process Elimination Module

#### FR-008: Supervised Kill Mode
- In Supervised Mode, when a process is classified as MALICIOUS:
  1. The agent SHALL generate a CRITICAL alert with full process details
  2. The agent SHALL present a **Kill / Ignore / Whitelist** action in the dashboard
  3. The administrator SHALL confirm before any kill action is executed

#### FR-009: Autonomous Kill Mode
- In Autonomous Mode, when a process is classified as MALICIOUS (score ≥ 0.85):
  1. The agent SHALL immediately send `SIGKILL` (Linux/macOS) or `TerminateProcess` (Windows)
  2. The agent SHALL log the kill action with: timestamp, PID, process name, threat score, AI classification, triggering heuristics
  3. The agent SHALL send a CRITICAL notification to the dashboard within 1 second of kill

#### FR-010: Kill Audit Log
- Every kill action SHALL be recorded in a tamper-evident audit log
- Audit log entries SHALL include: timestamp (ISO 8601), hostname, PID, process name, threat score, kill mode, authorized by (user/system), process executable SHA-256 hash

### 3.4 Dashboard — UI Requirements

#### FR-011: Device Overview
- Dashboard SHALL display a list of all monitored devices with: hostname, IP address, OS, agent version, last heartbeat, current threat level (GREEN/YELLOW/RED)

#### FR-012: Real-time Process Table
- Per-device process table SHALL update in real-time via WebSocket
- Table columns: PID, Process Name, CPU%, RAM, Net I/O, Threat Score, Status, Actions
- Processes classified as SUSPICIOUS or MALICIOUS SHALL be visually highlighted

#### FR-013: Alert Center
- Alert center SHALL display all active alerts sorted by severity
- Each alert SHALL show: severity, timestamp, device, description, recommended action
- Alerts SHALL support: Acknowledge, Dismiss, Escalate, Kill Process actions

#### FR-014: Network Topology Map
- Dashboard SHALL provide a visual network map showing: monitored devices, connections between devices, flagged external connections

#### FR-015: Audit Log Viewer
- Dashboard SHALL provide a searchable, filterable view of the audit log
- Filters: date range, device, severity, action type, user

### 3.5 Authentication & Authorization

#### FR-016: Authentication
- Dashboard SHALL support username + password authentication with bcrypt password hashing
- Multi-Factor Authentication (MFA) via TOTP (RFC 6238) SHALL be supported
- Session tokens SHALL expire after 8 hours of inactivity
- Failed login attempts SHALL be rate-limited to 5 attempts per 15 minutes

#### FR-017: Role-Based Access Control (RBAC)
- System SHALL enforce 4 roles as defined in Section 2.3
- Role assignments SHALL be audited

---

## 4. Non-Functional Requirements

### 4.1 Performance Requirements

| ID | Requirement | Metric |
|---|---|---|
| NFR-001 | AI inference latency | < 50ms per process batch |
| NFR-002 | Process scan cycle time | < 100ms per device |
| NFR-003 | Dashboard load time | < 2 seconds |
| NFR-004 | Alert delivery latency | < 500ms end-to-end |
| NFR-005 | Agent CPU overhead | < 3% average, < 10% peak |
| NFR-006 | Agent RAM usage | < 512MB |
| NFR-007 | Max concurrent agents | 50 per API server instance |

### 4.2 Reliability Requirements

| ID | Requirement |
|---|---|
| NFR-008 | Agent uptime: 99.9% (< 8.7 hours downtime/year) |
| NFR-009 | Agent SHALL auto-restart within 30 seconds of crash |
| NFR-010 | Dashboard failure SHALL NOT affect agent operation |
| NFR-011 | Data loss < 1 second of telemetry per agent crash |

### 4.3 Security Requirements

| ID | Requirement |
|---|---|
| NFR-012 | Agent-to-server communication: TLS 1.3 mandatory |
| NFR-013 | Stored data encrypted: AES-256-GCM |
| NFR-014 | Passwords stored as bcrypt hash (cost factor ≥ 12) |
| NFR-015 | Audit log integrity: SHA-256 hash chain |
| NFR-016 | No plaintext credentials in config files (use env vars or encrypted vault) |

### 4.4 Maintainability Requirements

- All agent modules SHALL have unit test coverage ≥ 80%
- All public API endpoints SHALL have integration tests
- Code SHALL follow language-specific style guides (PEP 8 for Python, rustfmt for Rust)

### 4.5 Usability Requirements

- Dashboard SHALL be responsive down to 1280px width
- Critical alerts SHALL be visible without scrolling on 1080p display
- Dashboard SHALL achieve WCAG 2.1 Level AA accessibility compliance

---

## 5. External Interface Requirements

### 5.1 REST API

- All API responses SHALL be JSON format
- API SHALL follow OpenAPI 3.0 specification
- Authentication: Bearer JWT token in Authorization header
- See [API Documentation](API_DOCUMENTATION.md) for full reference

### 5.2 WebSocket Interface

- Dashboard SHALL receive real-time telemetry via WebSocket (wss://)
- Message format: JSON
- Events: `process_update`, `alert_created`, `device_status_change`, `kill_action`

### 5.3 Agent Configuration File

- Format: YAML
- Location: `/etc/cyberguard/config.yaml` (Linux), `%PROGRAMDATA%\CyberGuard\config.yaml` (Windows)

---

## 6. System Constraints

1. AI model file SHALL not exceed 500MB
2. Agent SHALL work without internet access for core functionality
3. Agent SHALL not modify system files outside of its own data directory
4. Kill actions SHALL NOT be executed on PID 1 (init/systemd) under any circumstances
5. All kill actions on Windows SHALL use graceful termination first, forced after 5 seconds

---

*End of SRS v1.0*

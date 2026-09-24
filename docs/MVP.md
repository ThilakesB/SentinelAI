# MVP Document
## CyberGuard AI — Minimum Viable Product Scope

**Version:** 1.0  
**Date:** September 2026  
**Status:** Approved for Development

---

## 1. MVP Goal

Deliver a working, installable version of CyberGuard AI that a small organization's IT administrator can deploy on 1–5 servers within 30 minutes, and immediately begin receiving real-time AI-powered threat alerts — with the ability to kill suspicious processes from a central dashboard.

**MVP Success Statement:**  
> "An IT admin can install CyberGuard AI on their Linux server, see AI threat scores for every running process in real-time, receive alerts when suspicious activity is detected, and terminate threats with a single button click — all without any internet connection."

---

## 2. MVP Scope — What's IN

### Core Agent (Required for MVP)

| Feature | Details |
|---|---|
| **Process Scanner** | Enumerate all processes every 5 seconds; collect CPU, RAM, Net I/O |
| **On-Device AI Engine** | ONNX model classifies each process as SAFE / SUSPICIOUS / MALICIOUS |
| **Basic Heuristics** | CPU > 90%, RAM > 80%, network egress > 100MB/min rules |
| **Network Log Analysis** | Parse `/var/log/syslog`, basic connection anomaly detection |
| **Supervised Kill Mode** | Alert admin → admin confirms → process killed |
| **Whitelist Support** | Whitelist by process name or SHA-256 hash |
| **Kill Audit Log** | Local log file of all kill actions |
| **Agent Auto-restart** | Crash recovery via systemd/service manager |
| **Heartbeat to API** | Agent reports alive every 30 seconds |

### Dashboard & API (Required for MVP)

| Feature | Details |
|---|---|
| **Login Page** | Username + password authentication |
| **Device List** | Show all connected agents with status |
| **Process Table** | Real-time process list per device with threat scores |
| **Alert Panel** | List of SUSPICIOUS and MALICIOUS alerts with Kill/Ignore buttons |
| **Kill Action** | Single-click process termination from dashboard |
| **Audit Log View** | Read-only log viewer |
| **Basic Settings** | Configure scan interval, kill mode, thresholds |

### Platform Support (MVP)

- ✅ **Linux** (Ubuntu 20.04, Debian 11)
- ⚠️ **Windows Server 2019** — basic support, network log analysis limited
- ❌ **macOS** — excluded from MVP (v1.1)

---

## 3. MVP Scope — What's OUT

| Feature | Why Excluded | Target Version |
|---|---|---|
| Multi-Factor Authentication (MFA) | Adds complexity; low-risk for MVP beta | v1.1 |
| Autonomous Kill Mode | Risk too high without more testing | v1.1 |
| Power/Resource Prediction | Requires 7-day baseline data collection | v1.1 |
| Network Topology Map | Frontend complexity; not critical for MVP | v1.2 |
| Cloud Integration | By design deferred — on-device first | v2.0 |
| RBAC (Multi-role) | Admin-only for MVP is sufficient | v1.1 |
| Threat Intelligence Updates | Manual package update for MVP | v1.1 |
| macOS Support | Resource constraint | v1.1 |
| Mobile Dashboard | Not a priority for server monitoring | v2.0 |
| MSP Multi-tenant | Business feature, not core | v2.0 |
| Custom AI Model Training | Advanced feature for power users | v3.0 |

---

## 4. MVP Architecture Overview

```
[Monitored Server]
  └── CyberGuard Agent (Python + Rust)
        ├── Process Collector (psutil / Rust proc)
        ├── AI Engine (ONNX Runtime, local model)
        ├── Heuristic Rules Engine
        ├── Network Log Parser
        ├── Kill Executor
        └── WebSocket Client → [API Server]

[Admin Machine / Browser]
  └── CyberGuard Dashboard (React)
        └── HTTP/WebSocket → [API Server]

[API Server]
  └── FastAPI (Python)
        ├── REST API
        ├── WebSocket Hub
        └── SQLite Database
```

---

## 5. MVP Timeline

| Phase | Duration | Deliverables |
|---|---|---|
| **Phase 1: Foundation** | Weeks 1–3 | Agent skeleton, process collector, basic API server |
| **Phase 2: AI Engine** | Weeks 4–6 | ONNX model integration, threat scoring, heuristics |
| **Phase 3: Network Analysis** | Weeks 7–8 | Log ingestion, network anomaly detection |
| **Phase 4: Kill System** | Week 9 | Supervised kill mode, audit logging |
| **Phase 5: Dashboard** | Weeks 10–13 | Login, device list, process table, alerts, kill button |
| **Phase 6: Testing & QA** | Weeks 14–16 | Bug fixes, accuracy testing, security review |
| **Phase 7: Beta Launch** | Week 17–18 | Deploy to 10 beta customers |

**Total MVP Timeline: 18 weeks (4.5 months)**

---

## 6. MVP Acceptance Criteria

The MVP is considered complete when ALL of the following are true:

- [ ] Agent installs on Ubuntu 20.04 in under 5 minutes via provided script
- [ ] Agent starts automatically on boot via systemd service
- [ ] Dashboard is accessible via web browser on the local network
- [ ] AI threat scoring is visible for all running processes in real-time
- [ ] Suspicious processes (score > 0.3) appear highlighted in dashboard
- [ ] Kill button in dashboard successfully terminates a test malicious process
- [ ] Kill action is recorded in the audit log with timestamp and process details
- [ ] Agent continues running if dashboard connection is lost
- [ ] Agent CPU overhead is verified < 3% on a 4-core test server
- [ ] Agent RAM usage is verified < 512MB
- [ ] Detection rate ≥ 90% on internal test malware dataset
- [ ] Zero false-positive kills on whitelisted processes in 7-day soak test
- [ ] 10 beta testers can self-install and use without direct assistance

---

## 7. MVP Non-Goals (Explicitly Not Measured)

- Full MITRE ATT&CK coverage
- Zero false positive rate
- Sub-10ms detection latency
- Enterprise-grade availability SLA
- Multi-organization management

---

## 8. MVP Resource Requirements

| Resource | Details |
|---|---|
| **Engineering** | 2 backend devs, 1 AI/ML engineer, 1 frontend dev, 1 QA |
| **Infrastructure** | 3 test servers (1x Linux, 1x Windows, 1x macOS for later) |
| **AI Model** | Pre-trained on open malware datasets (EMBER, VirusShare samples) |
| **Duration** | 18 weeks |
| **Budget** | ~$150K (engineering salaries + infrastructure) |

---

*End of MVP Document v1.0*

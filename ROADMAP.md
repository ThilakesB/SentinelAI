# Roadmap
## CyberGuard AI — Development Plan & Milestones

**Version:** 1.0  
**Date:** September 2026  
**Planning Horizon:** 18 months

---

## Vision

Build the world's most trusted on-device AI cybersecurity platform for small and mid-sized organizations — delivering enterprise-grade threat detection at a fraction of the cost, with zero cloud dependency.

---

## Roadmap Overview

```
2026 Q4        2027 Q1        2027 Q2        2027 Q3        2027 Q4
   │              │              │              │              │
   ▼              ▼              ▼              ▼              ▼
[MVP v1.0]   [v1.1 Release] [v1.2 Release] [v2.0 Release] [v2.5 MSP]
   │              │              │              │              │
Foundation     macOS +        Network Map   Cloud Sync +    MSP Platform
+ Linux        MFA + RBAC   + Prediction   SIEM Integration + Marketplace
+ Windows      + Auto-kill   + Reporting
+ Dashboard
```

---

## Phase 1: MVP (v1.0) — Q4 2026

**Timeline:** Weeks 1–18 (October – January 2027)  
**Theme:** Core threat detection, supervised response, Linux/Windows foundation

### Milestones

| Milestone | Week | Deliverable |
|---|---|---|
| M1 | Week 3 | Agent scaffolding, process collector working on Linux |
| M2 | Week 6 | ONNX AI model integrated, threat scores visible |
| M3 | Week 8 | Network log analysis working (syslog) |
| M4 | Week 9 | Supervised kill mode operational |
| M5 | Week 13 | Full dashboard with real-time process table and alerts |
| M6 | Week 16 | QA complete, detection accuracy ≥ 90% |
| M7 | Week 18 | Beta launch with 10 customers |

### v1.0 Features
- ✅ On-device AI threat engine (ONNX)
- ✅ Process monitoring (Linux + Windows Server)
- ✅ Network log analysis (syslog, journald)
- ✅ Supervised kill mode (admin confirmation required)
- ✅ Real-time dashboard (single admin user)
- ✅ Kill audit log
- ✅ Whitelist management
- ✅ Basic email alerts

---

## Phase 2: v1.1 — Q1 2027

**Timeline:** February – March 2027 (6 weeks)  
**Theme:** Security hardening, autonomous response, macOS support

### v1.1 Features
- ✅ **macOS support** (Monterey 12+)
- ✅ **Autonomous kill mode** (auto-kill at configurable threshold)
- ✅ **Multi-Factor Authentication (MFA)** via TOTP
- ✅ **Role-Based Access Control (RBAC)** — 4 roles
- ✅ **Browser push notifications** for CRITICAL alerts
- ✅ **Threat intelligence package updates** via CLI command
- ✅ **Windows Event Log** ingestion improvements
- ✅ Performance tuning — agent CPU overhead reduced to < 2%

### Key Metrics Targets
- Detection rate: ≥ 93%
- False positive rate: < 1.5%
- Beta → paying customer conversion: ≥ 40%

---

## Phase 3: v1.2 — Q2 2027

**Timeline:** April – June 2027 (10 weeks)  
**Theme:** Visibility, prediction, reporting

### v1.2 Features
- ✅ **Network Topology Map** — visual network connection diagram
- ✅ **Resource Prediction Engine** — 7-day baseline anomaly prediction
- ✅ **Cross-device threat correlation** — detect lateral movement
- ✅ **Historical data analysis** — 90-day process history
- ✅ **PDF reporting** — weekly/monthly security posture reports
- ✅ **Device group management** — organize devices by environment
- ✅ **Alert suppression windows** — maintenance mode for scheduled tasks
- ✅ **Quarantine mode** — suspend process without killing

### Key Metrics Targets
- Paying customers: 200
- NPS score: ≥ 50
- Multi-device usage: ≥ 60% of customers monitor 5+ devices

---

## Phase 4: v2.0 — Q3 2027

**Timeline:** July – September 2027 (12 weeks)  
**Theme:** Cloud integration, SIEM connectivity, fleet management

### v2.0 Features
- ✅ **Optional Cloud Sync** — threat signatures shared across fleet (opt-in)
- ✅ **VirusTotal / OTX integration** — online threat intelligence enrichment
- ✅ **SIEM integration** — Splunk, Elastic SIEM, Wazuh forwarding
- ✅ **Webhook alerts** — push alerts to Slack, PagerDuty, Teams
- ✅ **REST API for external access** — programmatic threat data retrieval
- ✅ **AI model auto-update** — download updated models with signature verification
- ✅ **Encrypted cloud log backup** — optional off-site audit log backup
- ✅ **Mobile dashboard** (read-only) — iOS and Android companion app

### Key Metrics Targets
- Paying customers: 500
- ARR: $500K
- Enterprise pilots: 5

---

## Phase 5: v2.5 MSP Edition — Q4 2027

**Timeline:** October – December 2027 (10 weeks)  
**Theme:** Multi-tenant management, white-labeling, MSP channel

### v2.5 Features
- ✅ **Multi-tenant architecture** — MSPs manage multiple client organizations
- ✅ **White-label branding** — custom logo, colors, domain for MSP partners
- ✅ **MSP management portal** — fleet overview across all client organizations
- ✅ **Billing integration** — per-device usage tracking for MSP billing
- ✅ **SOC 2 Type II certification** (target)
- ✅ **GDPR/HIPAA compliance documentation** for regulated customers

### Key Metrics Targets
- MSP partners: 20
- Devices managed via MSP channel: 1,000+
- ARR: $1.5M

---

## Long-Term Vision (2028+)

| Initiative | Description |
|---|---|
| **Custom AI Model Training** | Allow organizations to train models on their own process baselines |
| **Zero-Trust Integration** | Integration with identity providers for device trust scoring |
| **Threat Hunting Module** | Proactive hunt mode for advanced persistent threats (APT) |
| **Container / Kubernetes Monitoring** | Extend agent to monitor Docker and Kubernetes workloads |
| **Hardware Security Monitoring** | Detect firmware-level threats via TPM and UEFI telemetry |
| **AI Explainability** | Show WHY the AI flagged a specific process with detailed reasoning |

---

## Known Risks to Roadmap

| Risk | Impact | Mitigation |
|---|---|---|
| AI model accuracy below target | Slips MVP acceptance | More training data, adjust thresholds |
| Performance overhead exceeds 3% | Requires architecture rework | Async agent design, profiling in CI |
| Windows kernel access restrictions | Limits network monitoring | Use ETW instead of raw packet capture |
| Slow customer acquisition | Slips revenue targets | Free tier, open-source community edition |
| Competition accelerates | Market positioning challenge | Double down on privacy differentiation |

---

## Feedback & Iteration

This roadmap is reviewed quarterly. Priorities shift based on:
1. Customer feedback (NPS surveys, support tickets)
2. Market changes (competitor releases, regulatory shifts)
3. Engineering velocity (actual vs. planned delivery)

All major roadmap changes will be documented in [CHANGELOG.md](../CHANGELOG.md).

---

*End of Roadmap v1.0*

# Changelog

All notable changes to CyberGuard AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- macOS Monterey 12+ agent support
- Autonomous kill mode (auto-terminate high-confidence threats)
- Multi-Factor Authentication (MFA) via TOTP
- Role-Based Access Control (RBAC) — 4 user roles
- Browser push notifications for CRITICAL alerts
- Resource prediction engine with 7-day baseline learning

---

## [1.0.0] — 2027-01-15 (Planned: MVP Release)

### Added

#### Core Agent (Linux + Windows Server)
- On-device AI threat engine using ONNX Runtime for zero-cloud-dependency inference
- Gradient-boosted decision tree model for process threat classification (SAFE / SUSPICIOUS / MALICIOUS)
- Process scanner: enumerates all running processes every 5 seconds with CPU%, RAM, Net I/O, disk I/O, open ports
- Heuristic rules engine with 5 built-in rules:
  - CPU > 90% sustained for > 60 seconds by a non-whitelisted process
  - RAM > 80% of total system RAM by a single process
  - Network egress > 100MB/min by non-update processes
  - Process accessing credential store paths
  - Process spawning > 50 child processes within 10 seconds
- Network log analysis: syslog, journald, Windows Event Log ingestion
- Network anomaly detectors: C2 beaconing, DNS tunneling, port scanning, data exfiltration
- Local IOC (Indicator of Compromise) database with 10,000+ known malicious IPs and domains
- Supervised kill mode: alert admin → admin confirms → process killed via SIGKILL / TerminateProcess
- Kill protection: PID 1, kernel processes, and configurable protected PID list can never be killed
- Tamper-evident audit log with SHA-256 hash chaining
- Process whitelist by name, executable SHA-256 hash, or signature issuer
- Auto-restart via systemd (Linux) / Windows Service on agent crash
- Heartbeat to API server every 30 seconds

#### API Server
- FastAPI REST API with OpenAPI 3.0 specification
- WebSocket hub for real-time telemetry streaming (dashboard ↔ agents)
- JWT authentication with 8-hour session expiry
- Rate limiting on login endpoint (5 attempts per 15 minutes)
- Device registry and agent management
- Alert lifecycle management (open → acknowledged → resolved)
- Audit log API with CSV/JSON export
- SQLite database (single-node) support
- Database schema with partitioned process_snapshots table

#### Dashboard (Web UI)
- Login page with JWT authentication
- Device overview: list of all connected devices with real-time status indicators
- Real-time process table per device (updates via WebSocket, no manual refresh)
- Alert center with severity-sorted alert feed and Kill/Quarantine/Whitelist/Dismiss actions
- Process detail modal with AI classification reasoning
- Audit log viewer with date/device/action filtering
- Settings page: scan interval, thresholds, kill mode configuration
- Dark mode interface (cybersecurity dashboard aesthetic)
- Responsive layout down to 1280px width

#### Security
- All agent-to-API communication over TLS 1.3
- Password storage with bcrypt (cost factor 12)
- Audit log tamper protection via database rules (no UPDATE/DELETE)
- Agent model integrity check: SHA-256 + Ed25519 signature verification before model load
- Agent runs with least-privilege OS account for telemetry; separate executor process for kill operations

---

## [0.9.0] — 2026-12-20 (Beta Release)

### Added
- Initial beta release for 10 selected beta customers
- Linux-only agent (Ubuntu 20.04, 22.04, Debian 11)
- Basic AI threat engine (ONNX model v0.9)
- Process monitoring and threat scoring
- Supervised kill mode (beta — requires admin confirmation)
- Minimal web dashboard (process table + alert panel only)
- SQLite database backend

### Known Issues (Beta)
- Windows agent not yet available
- MFA not yet implemented
- Dashboard shows "undefined" for processes with no network activity (fixed in v1.0.0)
- AI model produces higher false positive rate for Python development environments (threshold adjustment workaround: raise suspicious_threshold to 0.5)

---

## Version History

| Version | Release Date | Highlights |
|---|---|---|
| 1.0.0 | Jan 2027 (planned) | MVP: Linux + Windows, AI engine, supervised kill, dashboard |
| 0.9.0 | Dec 2026 | Beta: Linux only, 10 beta customers |

---

## Upcoming Versions

| Version | Target Date | Theme |
|---|---|---|
| 1.1.0 | Mar 2027 | macOS, MFA, RBAC, autonomous kill |
| 1.2.0 | Jun 2027 | Network map, resource prediction, reporting |
| 2.0.0 | Sep 2027 | Cloud sync, SIEM integration, mobile dashboard |
| 2.5.0 | Dec 2027 | MSP multi-tenant platform |

---

[Unreleased]: https://github.com/your-org/cyberguard-ai/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/cyberguard-ai/releases/tag/v1.0.0
[0.9.0]: https://github.com/your-org/cyberguard-ai/releases/tag/v0.9.0

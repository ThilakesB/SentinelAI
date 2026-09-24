# Test Plan
## CyberGuard AI — Testing Strategy

**Version:** 1.0  
**Date:** September 2026  
**Prepared By:** CyberGuard AI QA Team

---

## 1. Overview

This test plan defines the testing strategy, scope, approach, and resources required to validate CyberGuard AI v1.0 (MVP) before release.

### 1.1 Test Objectives

1. Verify that the AI threat engine correctly classifies processes with ≥ 90% accuracy
2. Validate that process kill actions work reliably across all supported platforms
3. Confirm that protected system PIDs (PID 1, kernel processes) can never be killed
4. Ensure the agent maintains < 3% CPU and < 512MB RAM overhead under all conditions
5. Verify authentication and authorization controls are correctly enforced
6. Validate real-time WebSocket communication between agent and dashboard
7. Confirm audit log integrity (hash chain verification)

---

## 2. Scope

### In Scope (v1.0 MVP)

| Area | Description |
|---|---|
| Agent (Linux) | Process monitoring, AI scoring, heuristics, log parsing, kill actions |
| Agent (Windows) | Basic process monitoring and kill (limited log analysis) |
| API Server | All REST endpoints, WebSocket, authentication, authorization |
| Dashboard | Login, process table, alert panel, kill button, audit log viewer |
| Integration | Agent ↔ API Server ↔ Dashboard end-to-end flows |
| Security | Auth bypass attempts, injection attacks, role boundary tests |
| Performance | Agent overhead, scan latency, concurrent device load |

### Out of Scope (v1.0)

- macOS agent (targeted for v1.1)
- Cloud sync (targeted for v2.0)
- Mobile dashboard
- MSP multi-tenant

---

## 3. Testing Levels

### 3.1 Unit Testing

**Tools:** pytest (Python), Rust's built-in test framework

| Component | Coverage Target | Key Tests |
|---|---|---|
| AI Inference Engine | 85% | Model loading, inference on known malicious/safe fixtures, threshold classification |
| Heuristic Rules | 90% | Each rule individually with boundary values |
| Log Parser | 80% | Valid log lines, malformed inputs, truncated entries |
| Kill Executor | 85% | Mock OS calls, verify correct signal sent, protected PID rejection |
| API Endpoints | 85% | Request validation, auth enforcement, response schema |
| Auth Module | 90% | Token generation/validation, expiry, MFA verification |
| Audit Log | 95% | Hash chain computation, append-only enforcement |

---

### 3.2 Integration Testing

**Tools:** pytest with test containers, httpx for API testing

| Test Suite | Description |
|---|---|
| **Agent-API Connection** | Agent WebSocket connects, authenticates, streams telemetry |
| **Alert Pipeline** | AI flags process → alert created in DB → dashboard receives via WS |
| **Kill Flow** | Kill action from dashboard → API → agent → OS kill → audit log |
| **Whitelist Flow** | Whitelist added → agent applies → process no longer scored |
| **Reconnection** | Agent disconnects and reconnects, no data loss |
| **Multi-agent** | 5 agents simultaneously connected, all data flows correctly |

---

### 3.3 AI / ML Testing

**Tools:** pytest, scikit-learn metrics, custom test dataset

#### Detection Accuracy Testing

| Dataset | Description | Target |
|---|---|---|
| Clean Processes | 500 samples of known-good processes (web servers, databases, system tools) | False Positive Rate < 5% |
| Known Malware | 200 samples of malware process behavior (cryptominer, C2 agent, keylogger) | True Positive Rate > 90% |
| Edge Cases | 50 borderline processes (legitimate high-CPU tools, dev tools) | Accuracy > 80% |
| Novel Processes | 100 processes not seen during training | Graceful degradation, no crash |

#### Heuristic Rule Testing

| Rule | Test Case | Expected |
|---|---|---|
| CPU > 90% | Simulate process at 95% CPU for 65s | SUSPICIOUS alert fired |
| CPU > 90% | Process at 95% CPU for 55s | No alert (< 60s threshold) |
| RAM > 80% | Process consuming 85% of total RAM | SUSPICIOUS alert fired |
| Net egress > 100MB/min | Simulate high outbound traffic | SUSPICIOUS alert fired |
| Spawn > 50 children | Fork bomb simulation (contained) | SUSPICIOUS alert fired |

---

### 3.4 Security Testing

**Tools:** OWASP ZAP, custom penetration scripts, Burp Suite

| Category | Test | Expected |
|---|---|---|
| **Authentication** | API access without JWT token | 401 Unauthorized |
| **Authentication** | Expired JWT token | 401 Unauthorized |
| **Authentication** | Forged JWT token | 401 Unauthorized |
| **Authorization** | Viewer role attempting kill action | 403 Forbidden |
| **Authorization** | IT Admin accessing another org's data | 403 Forbidden |
| **Rate Limiting** | 10 failed login attempts in 1 minute | Account locked after 5 |
| **SQL Injection** | Injected strings in API params | Sanitized, no DB error |
| **XSS** | Script tags in process name field | Sanitized in dashboard |
| **IDOR** | Access another device's data by guessing UUID | 403/404 |
| **Kill Guard** | API kill request for PID 1 | 409 Conflict — protected |
| **TLS** | HTTP request to API (not HTTPS) | Redirect to HTTPS or rejected |
| **Audit Tampering** | Direct DB UPDATE on audit_log table | Rule prevents it |

---

### 3.5 Performance Testing

**Tools:** Locust (load testing), cAdvisor (agent resource monitoring)

#### Agent Performance Tests

| Scenario | Condition | Target |
|---|---|---|
| Idle overhead | System with 50 processes, no threats | < 0.5% CPU, < 256MB RAM |
| Normal load | System with 200 processes, mixed threat levels | < 2% CPU, < 400MB RAM |
| Peak load | System with 500 processes, 10% malicious | < 3% CPU, < 512MB RAM |
| Scan latency | Time to complete one full scan cycle | < 100ms |
| AI inference | Time per process batch (50 processes) | < 50ms |

#### API Server Load Tests

| Scenario | Condition | Target |
|---|---|---|
| Concurrent agents | 20 agents simultaneously connected | No dropped connections, p99 latency < 500ms |
| Alert throughput | 100 alerts/second from agents | All stored, dashboard receives all |
| Kill action | 10 concurrent kill requests | All executed correctly, no race conditions |

---

### 3.6 Acceptance Testing (UAT)

10 beta customers will perform UAT over a 2-week period with the following scenarios:

1. Self-install agent on their server without assistance
2. View their process list in the dashboard
3. Receive and acknowledge a test alert (we simulate a suspicious process)
4. Execute a kill action on the simulated threat
5. Verify the kill appears in the audit log
6. Add a whitelist entry for a known-good process

**UAT Success Criteria:**
- ≥ 8/10 customers complete all 6 steps without support intervention
- NPS score ≥ 40 after UAT period

---

## 4. Test Environment

### Environment Setup

| Environment | Purpose | Infrastructure |
|---|---|---|
| **Dev** | Developer testing during feature development | Local Docker Compose |
| **QA** | Automated test runs (CI pipeline) | GitHub Actions + 3 VMs |
| **Staging** | Pre-release integration and UAT | 3 VMs: Ubuntu, Windows Server, API server |
| **Production** | Live environment | Cloud VMs (after beta launch) |

### Test Machines

| Machine | OS | Role |
|---|---|---|
| test-linux-01 | Ubuntu 22.04 LTS | Linux agent testing |
| test-windows-01 | Windows Server 2019 | Windows agent testing |
| test-api-01 | Ubuntu 22.04 LTS | API server + dashboard |

---

## 5. Test Exit Criteria

| Criteria | Requirement |
|---|---|
| Unit test pass rate | ≥ 95% |
| Code coverage | ≥ 80% |
| AI detection accuracy | ≥ 90% on validation set |
| False positive rate | < 5% |
| Security test findings | Zero critical or high severity issues unresolved |
| Performance overhead | Agent ≤ 3% CPU, ≤ 512MB RAM confirmed |
| Protected PID kill rejection | 100% — zero exceptions |
| Audit log hash chain | Valid on 100% of entries |
| UAT completion | ≥ 8/10 beta customers complete all scenarios |

---

## 6. Defect Classification

| Severity | Definition | SLA for Fix |
|---|---|---|
| **Critical (P0)** | Data loss, security breach, system crash, protected PID can be killed | Fix before release |
| **High (P1)** | Core feature broken, incorrect threat classification on known malware | Fix before release |
| **Medium (P2)** | Non-critical feature broken, UI issue affecting usability | Fix in next patch release |
| **Low (P3)** | Cosmetic issue, minor UX improvement | Backlog |

---

## 7. Test Schedule

| Activity | Duration | Start |
|---|---|---|
| Unit test implementation | Ongoing with development | Week 1 |
| Integration test implementation | Weeks 10–13 | Week 10 |
| AI accuracy validation | Week 14 | Week 14 |
| Security penetration testing | Week 14–15 | Week 14 |
| Performance testing | Week 15 | Week 15 |
| UAT (beta customers) | 2 weeks | Week 17 |
| Final regression | Week 18 | Week 18 |

---

*End of Test Plan v1.0*

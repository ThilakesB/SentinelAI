# Architecture Document
## CyberGuard AI — System Design & Architecture

**Version:** 1.0  
**Date:** September 2026  
**Author:** CyberGuard AI Engineering Team

---

## 1. Architecture Overview

CyberGuard AI follows a **distributed agent-server architecture** where lightweight monitoring agents run on each protected machine and report to a central API server. All critical AI inference happens locally on each agent machine — preserving privacy and enabling offline operation.

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ORGANIZATION NETWORK                          │
│                                                                      │
│  ┌──────────────────────┐    ┌──────────────────────┐               │
│  │     MACHINE A        │    │     MACHINE B        │  ...          │
│  │  ┌────────────────┐  │    │  ┌────────────────┐  │               │
│  │  │ CyberGuard     │  │    │  │ CyberGuard     │  │               │
│  │  │ Agent          │  │    │  │ Agent          │  │               │
│  │  │ ┌────────────┐ │  │    │  │ ┌────────────┐ │  │               │
│  │  │ │ AI Engine  │ │  │    │  │ │ AI Engine  │ │  │               │
│  │  │ │ (on-device)│ │  │    │  │ │ (on-device)│ │  │               │
│  │  │ └────────────┘ │  │    │  │ └────────────┘ │  │               │
│  │  └────────────────┘  │    │  └────────────────┘  │               │
│  └──────────┬───────────┘    └──────────┬───────────┘               │
│             │  WebSocket (TLS 1.3)       │                           │
│             └────────────┬──────────────┘                           │
│                          │                                           │
│                 ┌────────▼────────┐                                  │
│                 │   API SERVER    │                                  │
│                 │   (FastAPI)     │                                  │
│                 │  ┌───────────┐  │                                  │
│                 │  │ SQLite /  │  │                                  │
│                 │  │ PostgreSQL│  │                                  │
│                 │  └───────────┘  │                                  │
│                 └────────┬────────┘                                  │
│                          │ HTTP / WebSocket                          │
│                 ┌────────▼────────┐                                  │
│                 │   DASHBOARD     │                                  │
│                 │   (React SPA)   │                                  │
│                 └─────────────────┘                                  │
│                                                                      │
│  ┄ ┄ ┄ ┄ ┄ ┄ Optional Cloud Channel (opt-in) ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄ ┄   │
│             ┌─────────────────────────────┐                          │
│             │  Threat Intel Feed / Cloud  │                          │
│             │  Sync / Encrypted Log Backup│                          │
│             └─────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 CyberGuard Agent

The agent is the core of the system. It runs as a background service (daemon) on each monitored machine with root/admin privileges.

**Agent Internal Architecture:**

```
┌─────────────────────────────────────────────────────┐
│                   CYBERGUARD AGENT                   │
│                                                      │
│  ┌─────────────────┐    ┌─────────────────────────┐  │
│  │  COLLECTOR      │    │    AI THREAT ENGINE      │  │
│  │                 │    │                          │  │
│  │ • Process enum  │───►│  ONNX Runtime Model      │  │
│  │ • CPU/RAM/IO    │    │  (on-device inference)   │  │
│  │ • Net metrics   │    │                          │  │
│  │ • Open ports    │    │  Threat Score: 0.0–1.0   │  │
│  └────────┬────────┘    └────────────┬─────────────┘  │
│           │                          │                 │
│  ┌────────▼────────┐    ┌────────────▼─────────────┐  │
│  │  LOG PARSER     │    │   HEURISTIC RULES ENGINE  │  │
│  │                 │    │                           │  │
│  │ • syslog        │    │ • CPU > 90% rules         │  │
│  │ • journald      │    │ • RAM > 80% rules         │  │
│  │ • Windows EVT   │    │ • Network egress rules    │  │
│  │ • Zeek logs     │    │ • Child process spawn     │  │
│  └────────┬────────┘    └────────────┬──────────────┘  │
│           │                          │                 │
│  ┌────────▼──────────────────────────▼──────────────┐  │
│  │              ALERT AGGREGATOR                     │  │
│  │   Combines AI scores + heuristics → final alert   │  │
│  └────────────────────────┬──────────────────────────┘  │
│                           │                             │
│  ┌────────────────────────▼──────────────────────────┐  │
│  │              ACTION EXECUTOR                       │  │
│  │   • Supervised Mode: Send alert, await response    │  │
│  │   • Autonomous Mode: Kill immediately              │  │
│  │   • Write to Audit Log                             │  │
│  └────────────────────────┬──────────────────────────┘  │
│                           │                             │
│  ┌────────────────────────▼──────────────────────────┐  │
│  │         WEBSOCKET CLIENT (TLS 1.3)                 │  │
│  │   Streams telemetry + events to API Server         │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**Agent Technology Stack:**
- **Language:** Python 3.11+ (main logic) + Rust (performance-critical process enumeration)
- **AI Inference:** ONNX Runtime 1.16+
- **Process Collection:** `psutil` (Python), custom Rust `procfs` reader
- **Network Capture:** `scapy` (Python), `libpcap`
- **Log Parsing:** Custom Python parser with `watchdog` for file watching
- **Service Management:** systemd unit (Linux), Windows Service (Windows), launchd plist (macOS)

---

### 2.2 API Server

The API Server is the central hub connecting all agents to the dashboard. It is stateless and horizontally scalable.

**Responsibilities:**
- Receive and store telemetry from agents
- Serve REST API for dashboard
- Broker WebSocket connections (dashboard ↔ agent events)
- Store alerts, audit logs, device registry
- Authenticate users and issue JWT tokens

**Technology Stack:**
- **Language:** Python 3.11+
- **Framework:** FastAPI 0.100+
- **WebSocket:** FastAPI WebSocket (Starlette)
- **Database:** SQLite (single-node), PostgreSQL 14+ (multi-node)
- **ORM:** SQLAlchemy 2.0 (async)
- **Auth:** PyJWT, passlib (bcrypt)
- **Task Queue:** Celery + Redis (for background jobs like report generation)

---

### 2.3 Dashboard (Frontend)

Single-page application providing the monitoring and management interface.

**Technology Stack:**
- **Framework:** React 18 + TypeScript
- **Build Tool:** Vite 5
- **State Management:** Zustand
- **Real-time:** native WebSocket API
- **Charts:** Recharts
- **UI Components:** Radix UI + custom CSS
- **HTTP Client:** Axios

---

## 3. Data Flow

### 3.1 Threat Detection Flow

```
[OS Kernel / Process Table]
         │
         ▼ (every 5 seconds)
[Agent: Process Collector]
         │ raw process telemetry
         ▼
[Agent: AI Engine + Heuristics]
         │ threat score per process
         ▼
[Agent: Alert Aggregator]
         │ if score > threshold:
         ▼
[Agent: WebSocket → API Server]
         │ alert JSON payload
         ▼
[API Server: Alert Storage]
         │ persist to DB
         ▼
[API Server: WebSocket Broadcast]
         │ push to all dashboard clients
         ▼
[Dashboard: Alert Panel]
         │ user sees alert
         ▼
[User: Kill / Ignore / Whitelist]
         │ action sent via REST API
         ▼
[API Server: Kill Command]
         │ forwarded to agent via WebSocket
         ▼
[Agent: Kill Executor]
         │ SIGKILL / TerminateProcess
         ▼
[Audit Log: Kill Event Recorded]
```

### 3.2 Network Log Analysis Flow

```
[OS Log Files: syslog, EVT, journald]
         │ (watchdog file tail)
         ▼
[Agent: Log Parser]
         │ parsed log events
         ▼
[Agent: Network Anomaly Detector]
         │ checks against patterns + local IOC DB
         ▼
[Agent: Alert Generation]
         │ network_alert JSON
         ▼
[API Server → Dashboard]
         (same alert flow as above)
```

---

## 4. Database Schema (High-Level)

### Core Tables

```sql
-- Devices registered with the API server
devices (id, hostname, ip_address, os, agent_version, last_heartbeat, status)

-- Process snapshots per scan cycle
process_snapshots (id, device_id, pid, name, cpu_pct, ram_mb, 
                   net_sent_bytes, net_recv_bytes, threat_score, 
                   classification, timestamp)

-- All alerts generated (process + network)
alerts (id, device_id, alert_type, severity, title, description,
        pid, process_name, threat_score, network_src, network_dst,
        status, created_at, resolved_at)

-- Kill/action audit log
audit_log (id, device_id, action_type, pid, process_name, threat_score,
           mode, performed_by, timestamp, prev_hash, entry_hash)

-- User accounts
users (id, username, email, password_hash, role, mfa_secret, 
       is_mfa_enabled, last_login, created_at)

-- Process whitelist
whitelist (id, device_id, rule_type, rule_value, added_by, added_at)
```

> Full schema with indexes and constraints: see [Database Design Document](DATABASE_DESIGN.md)

---

## 5. Security Architecture

### 5.1 Defense in Depth

```
Layer 1: Network Transport      TLS 1.3 (agent ↔ API server, browser ↔ dashboard)
Layer 2: Authentication         JWT tokens + MFA (TOTP)
Layer 3: Authorization          RBAC (4 roles, enforced in API middleware)
Layer 4: Data at Rest           AES-256-GCM for sensitive fields
Layer 5: Audit Integrity        SHA-256 hash chain on audit log
Layer 6: Agent Security         Runs with least-privilege OS account (except kill ops)
Layer 7: Kill Safety Guards     PID 1 / kernel process exclusion list
```

### 5.2 Agent Security Boundaries

The agent process:
- Runs as `cyberguard` system user (low privilege) for telemetry collection
- Escalates to root/SYSTEM only for kill operations, using a separate `cyberguard-executor` subprocess with restricted capabilities
- Never opens external network connections (all comms go to API server)
- AI model is verified with SHA-256 hash before loading

---

## 6. Scalability Design

### Single-Node (MVP)

```
1 API Server (FastAPI + SQLite)
Up to 20 agents connected
Suitable for: small organizations (1–20 servers)
```

### Multi-Node (v1.2+)

```
Load Balancer (nginx)
    │
    ├── API Server Node 1 (FastAPI)
    ├── API Server Node 2 (FastAPI)
    └── API Server Node N (FastAPI)
    
Shared PostgreSQL (primary + replica)
Shared Redis (for WebSocket pub/sub and task queue)

Capacity: 50+ agents, 1000+ devices (with horizontal scaling)
```

---

## 7. Deployment Architecture

### Docker Compose (Recommended for Self-Hosted)

```yaml
services:
  api:        # FastAPI API server
  dashboard:  # nginx serving React build
  db:         # PostgreSQL
  redis:      # Redis for pub/sub + task queue
  agent:      # Optional: run agent in container (for containerized workloads)
```

> Full deployment instructions: see [Deployment Guide](DEPLOYMENT_GUIDE.md)

---

## 8. AI Model Architecture

### Model Selection

The on-device threat classification model is a **gradient-boosted decision tree** converted to ONNX format using XGBoost or LightGBM.

**Why not a neural network?**
- Gradient boosted trees achieve comparable accuracy on tabular process data
- 10–50x smaller model file size (< 50MB vs. hundreds of MB for neural nets)
- Faster inference on CPU-only hardware
- Better interpretability for explaining classifications

### Input Features (per process)

```
cpu_pct                 (float)   - CPU usage percentage
ram_mb                  (float)   - RAM usage in megabytes
net_sent_bytes_per_sec  (float)   - Network bytes sent per second
net_recv_bytes_per_sec  (float)   - Network bytes received per second
disk_read_mb_per_sec    (float)   - Disk read MB per second
disk_write_mb_per_sec   (float)   - Disk write MB per second
open_ports_count        (int)     - Number of open network ports
child_process_count     (int)     - Number of child processes
process_age_seconds     (int)     - How long process has been running
is_signed               (bool)    - Digital signature valid?
parent_pid_is_known     (bool)    - Is parent PID a trusted process?
name_entropy            (float)   - Shannon entropy of process name (detects random names)
```

### Training Data

- EMBER malware dataset (open-source)
- VirusShare PE sample metadata
- Internal clean process baseline from 50+ server environments
- Synthetic anomalies (cryptominer behavior patterns)

### Model Update Mechanism

- Models shipped as versioned `.onnx` files in update packages
- Agent verifies SHA-256 + Ed25519 signature before loading new model
- Rollback to previous model if new model produces > 5% false positive rate in 1-hour window

---

*End of Architecture Document v1.0*

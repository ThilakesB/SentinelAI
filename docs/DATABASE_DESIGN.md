# Database Design Document (DBD)
## CyberGuard AI — Database Schema & ER Diagrams

**Version:** 1.0  
**Date:** September 2026  
**Database:** SQLite (single-node), PostgreSQL 14+ (multi-node)

---

## 1. Overview

CyberGuard AI uses a relational database to store:
- Device registry and agent heartbeat data
- Process telemetry snapshots
- Security alerts and their lifecycle
- Kill/response action audit log
- User accounts and session data
- Whitelist rules

The schema is designed with:
- **Append-only** patterns for telemetry and audit data (no UPDATE/DELETE on audit rows)
- **Audit log hash chaining** for tamper evidence
- **Index optimization** on time-series queries (device + timestamp)

---

## 2. Entity Relationship Diagram

```
┌──────────────────┐         ┌──────────────────────┐
│     devices      │         │    process_snapshots  │
│──────────────────│         │──────────────────────│
│ id (PK)          │◄────────│ device_id (FK)       │
│ hostname         │         │ id (PK)              │
│ ip_address       │         │ scan_batch_id        │
│ os_type          │         │ pid                  │
│ os_version       │         │ name                 │
│ agent_version    │         │ cpu_pct              │
│ api_key_hash     │         │ ram_mb               │
│ status           │         │ net_sent_bps         │
│ last_heartbeat   │         │ net_recv_bps         │
│ created_at       │         │ disk_read_mbps       │
│ updated_at       │         │ disk_write_mbps      │
└──────────────────┘         │ open_ports_count     │
         │                   │ child_process_count  │
         │                   │ threat_score         │
         │                   │ classification       │
         │                   │ executable_path      │
         │                   │ exe_sha256           │
         │                   │ is_signed            │
         │                   │ timestamp            │
         │                   └──────────────────────┘
         │
         │              ┌──────────────────────┐
         │              │       alerts         │
         └─────────────►│──────────────────────│
                        │ id (PK)              │
                        │ device_id (FK)       │
                        │ alert_type           │
                        │ severity             │
                        │ title                │
                        │ description          │
                        │ pid                  │
                        │ process_name         │
                        │ threat_score         │
                        │ network_src_ip       │
                        │ network_dst_ip       │
                        │ network_dst_port     │
                        │ ioc_matched          │
                        │ status               │
                        │ acknowledged_by (FK) │
                        │ created_at           │
                        │ resolved_at          │
                        └──────────────────────┘
         │
         │              ┌──────────────────────┐
         └─────────────►│     audit_log        │
                        │──────────────────────│
                        │ id (PK)              │
                        │ device_id (FK)       │
                        │ action_type          │
                        │ pid                  │
                        │ process_name         │
                        │ exe_sha256           │
                        │ threat_score         │
                        │ kill_mode            │
                        │ performed_by (FK)    │
                        │ timestamp            │
                        │ prev_entry_hash      │
                        │ entry_hash           │
                        └──────────────────────┘

┌──────────────────┐         ┌──────────────────────┐
│      users       │         │     whitelist_rules  │
│──────────────────│         │──────────────────────│
│ id (PK)          │         │ id (PK)              │
│ username         │         │ device_id (FK, null) │
│ email            │         │ scope (device/global)│
│ password_hash    │         │ rule_type            │
│ role             │         │ rule_value           │
│ mfa_secret       │         │ description          │
│ is_mfa_enabled   │         │ added_by (FK)        │
│ is_active        │         │ added_at             │
│ last_login       │         └──────────────────────┘
│ created_at       │
└──────────────────┘

┌──────────────────────┐
│  device_baselines    │
│──────────────────────│
│ id (PK)              │
│ device_id (FK)       │
│ metric_name          │
│ mean_value           │
│ std_deviation        │
│ sample_count         │
│ baseline_start       │
│ baseline_end         │
│ updated_at           │
└──────────────────────┘
```

---

## 3. Table Definitions

### 3.1 `devices`

Stores metadata about each machine running a CyberGuard agent.

```sql
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        VARCHAR(255) NOT NULL,
    ip_address      INET NOT NULL,
    os_type         VARCHAR(20) NOT NULL CHECK (os_type IN ('linux', 'windows', 'macos')),
    os_version      VARCHAR(100),
    agent_version   VARCHAR(20) NOT NULL,
    api_key_hash    VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 of agent API key
    status          VARCHAR(20) NOT NULL DEFAULT 'active' 
                        CHECK (status IN ('active', 'inactive', 'disconnected')),
    threat_level    VARCHAR(10) NOT NULL DEFAULT 'green'
                        CHECK (threat_level IN ('green', 'yellow', 'red')),
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_last_heartbeat ON devices(last_heartbeat);
```

---

### 3.2 `process_snapshots`

Stores time-series process telemetry data. High write volume — partitioned by month in PostgreSQL.

```sql
CREATE TABLE process_snapshots (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scan_batch_id       UUID NOT NULL,               -- Groups all processes from one scan cycle
    pid                 INTEGER NOT NULL,
    name                VARCHAR(255) NOT NULL,
    parent_pid          INTEGER,
    cpu_pct             REAL NOT NULL DEFAULT 0,
    ram_mb              REAL NOT NULL DEFAULT 0,
    net_sent_bps        REAL NOT NULL DEFAULT 0,     -- Bytes per second sent
    net_recv_bps        REAL NOT NULL DEFAULT 0,     -- Bytes per second received
    disk_read_mbps      REAL NOT NULL DEFAULT 0,
    disk_write_mbps     REAL NOT NULL DEFAULT 0,
    open_ports_count    SMALLINT NOT NULL DEFAULT 0,
    child_process_count SMALLINT NOT NULL DEFAULT 0,
    threat_score        REAL,                        -- NULL if whitelisted
    classification      VARCHAR(20) CHECK (
                            classification IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS', 'WHITELISTED')
                        ),
    executable_path     TEXT,
    exe_sha256          CHAR(64),
    is_signed           BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);

-- Monthly partitions
CREATE TABLE process_snapshots_2026_10 
    PARTITION OF process_snapshots 
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE INDEX idx_ps_device_time ON process_snapshots(device_id, timestamp DESC);
CREATE INDEX idx_ps_threat_score ON process_snapshots(threat_score) 
    WHERE threat_score > 0.3;
CREATE INDEX idx_ps_scan_batch ON process_snapshots(scan_batch_id);
```

---

### 3.3 `alerts`

Stores all security alerts — both process-based and network-based.

```sql
CREATE TABLE alerts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    alert_type          VARCHAR(30) NOT NULL CHECK (
                            alert_type IN (
                                'malicious_process', 'suspicious_process',
                                'network_c2_beacon', 'network_dns_tunnel',
                                'network_port_scan', 'network_exfiltration',
                                'resource_anomaly', 'heuristic_trigger'
                            )
                        ),
    severity            VARCHAR(10) NOT NULL CHECK (
                            severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
                        ),
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    pid                 INTEGER,
    process_name        VARCHAR(255),
    process_exe_path    TEXT,
    threat_score        REAL,
    network_src_ip      INET,
    network_dst_ip      INET,
    network_dst_port    INTEGER,
    network_protocol    VARCHAR(10),
    ioc_matched         VARCHAR(255),              -- Which IOC triggered this alert
    raw_evidence        JSONB,                     -- Raw log lines / process data
    status              VARCHAR(20) NOT NULL DEFAULT 'open' 
                            CHECK (status IN ('open', 'acknowledged', 'resolved', 'dismissed')),
    acknowledged_by     UUID REFERENCES users(id),
    acknowledged_at     TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_device_time ON alerts(device_id, created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity, status);
CREATE INDEX idx_alerts_status ON alerts(status) WHERE status = 'open';
```

---

### 3.4 `audit_log`

Append-only table with hash chaining for tamper evidence. No UPDATE or DELETE permitted.

```sql
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID REFERENCES devices(id),
    action_type     VARCHAR(30) NOT NULL CHECK (
                        action_type IN (
                            'kill_process', 'whitelist_add', 'whitelist_remove',
                            'settings_change', 'user_login', 'user_logout',
                            'agent_start', 'agent_stop', 'model_update'
                        )
                    ),
    pid             INTEGER,
    process_name    VARCHAR(255),
    exe_sha256      CHAR(64),
    threat_score    REAL,
    kill_mode       VARCHAR(20) CHECK (kill_mode IN ('supervised', 'autonomous')),
    performed_by    UUID REFERENCES users(id),    -- NULL for autonomous actions
    details         JSONB,                         -- Additional context
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_entry_hash CHAR(64),                      -- SHA-256 of previous row
    entry_hash      CHAR(64) NOT NULL              -- SHA-256 of this row (for chain)
);

-- Prohibit modifications to audit log
CREATE RULE no_update_audit AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO audit_log DO INSTEAD NOTHING;

CREATE INDEX idx_audit_device_time ON audit_log(device_id, timestamp DESC);
CREATE INDEX idx_audit_type ON audit_log(action_type);
```

---

### 3.5 `users`

Dashboard user accounts.

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(50) NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,          -- bcrypt hash, cost 12+
    role            VARCHAR(20) NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('super_admin', 'security_analyst', 
                                        'it_admin', 'viewer')),
    mfa_secret      VARCHAR(255),                   -- TOTP secret (encrypted at rest)
    is_mfa_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login      TIMESTAMPTZ,
    login_attempts  SMALLINT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### 3.6 `whitelist_rules`

Process whitelist entries.

```sql
CREATE TABLE whitelist_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID REFERENCES devices(id) ON DELETE CASCADE,  -- NULL = global
    scope           VARCHAR(10) NOT NULL DEFAULT 'device'
                        CHECK (scope IN ('device', 'global')),
    rule_type       VARCHAR(20) NOT NULL CHECK (
                        rule_type IN ('process_name', 'exe_sha256', 'signature_issuer')
                    ),
    rule_value      VARCHAR(500) NOT NULL,
    description     TEXT,
    added_by        UUID NOT NULL REFERENCES users(id),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_whitelist_unique ON whitelist_rules(
    COALESCE(device_id::text, 'global'), rule_type, rule_value
);
```

---

### 3.7 `device_baselines`

Statistical baseline per device per metric — used for anomaly prediction.

```sql
CREATE TABLE device_baselines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    metric_name     VARCHAR(50) NOT NULL,           -- e.g. 'cpu_pct', 'ram_mb'
    mean_value      DOUBLE PRECISION NOT NULL,
    std_deviation   DOUBLE PRECISION NOT NULL,
    p95_value       DOUBLE PRECISION,
    sample_count    INTEGER NOT NULL,
    baseline_start  TIMESTAMPTZ NOT NULL,
    baseline_end    TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE (device_id, metric_name)
);
```

---

## 4. Data Retention Policy

| Table | Retention | Strategy |
|---|---|---|
| `process_snapshots` | 90 days | Partition drop (older partitions deleted monthly) |
| `alerts` | 1 year | Soft-delete (status = 'archived') |
| `audit_log` | 3 years | Never deleted (compliance requirement) |
| `device_baselines` | Rolling 7-day window + summary | Updated in place |
| `users` | Indefinite | Soft-delete (is_active = false) |

---

## 5. Migration Strategy

Database migrations are managed using **Alembic** (Python).

```bash
# Create a new migration
alembic revision --autogenerate -m "add_quarantine_status_to_alerts"

# Apply migrations
alembic upgrade head

# Rollback one revision
alembic downgrade -1
```

All migrations are stored in `db/migrations/` and are version-controlled.

---

*End of Database Design Document v1.0*

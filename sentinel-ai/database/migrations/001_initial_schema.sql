-- ============================================================
--  Migration 001: Initial SentinelAI schema
--  Database: Supabase PostgreSQL
--  Run: psql $DATABASE_URL -f 001_initial_schema.sql
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────
--  USERS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT UNIQUE NOT NULL,
    hashed_pw   TEXT,
    api_key     TEXT UNIQUE,
    role        VARCHAR(20) NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);
COMMENT ON TABLE users IS 'SentinelAI user accounts with role-based access.';

-- ─────────────────────────────────────────────────────────────
--  SETTINGS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value_json  JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Seed default settings
INSERT INTO settings (key, value_json) VALUES
    ('monitoring_interval_sec',          '5'),
    ('cpu_anomaly_threshold',            '85'),
    ('ram_anomaly_threshold',            '80'),
    ('auto_kill_critical',               'false'),
    ('auto_block_ip_critical',           'true'),
    ('abuseipdb_score_threshold',        '75'),
    ('threat_intel_refresh_hours',       '6'),
    ('ml_anomaly_suspicious_threshold',  '-0.1'),
    ('ml_anomaly_critical_threshold',    '-0.3'),
    ('ml_retrain_hour',                  '3')
ON CONFLICT (key) DO NOTHING;

-- ─────────────────────────────────────────────────────────────
--  THREAT EVENTS (created first — referenced by snapshots)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_events (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    threat_level      VARCHAR(20) NOT NULL
                        CHECK (threat_level IN ('Normal', 'Suspicious', 'Critical')),
    anomaly_score     NUMERIC(8,4),
    trigger_type      VARCHAR(50)
                        CHECK (trigger_type IN ('process', 'network', 'hash_match', 'yara_match')),
    feature_vector    JSONB,
    top_features      JSONB,
    process_id        UUID,           -- FK added after processes_snapshot is created
    network_id        UUID,           -- FK added after network_connections is created
    ml_model_version  VARCHAR(50),
    is_resolved       BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at       TIMESTAMPTZ,
    notes             TEXT
);
CREATE INDEX IF NOT EXISTS idx_threat_detected   ON threat_events(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_level      ON threat_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_threat_unresolved ON threat_events(is_resolved)
    WHERE is_resolved = FALSE;
COMMENT ON TABLE threat_events IS 'AI-classified threat events with feature explanations.';

-- ─────────────────────────────────────────────────────────────
--  PROCESSES SNAPSHOT
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS processes_snapshot (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pid             INTEGER NOT NULL,
    name            VARCHAR(255) NOT NULL,
    exe_path        TEXT,
    exe_hash        VARCHAR(64),        -- SHA-256 hex
    cpu_percent     NUMERIC(5,2),
    ram_mb          NUMERIC(10,2),
    disk_read_mb    NUMERIC(10,2),
    disk_write_mb   NUMERIC(10,2),
    net_sent_mb     NUMERIC(10,2),
    net_recv_mb     NUMERIC(10,2),
    start_time      TIMESTAMPTZ,
    parent_pid      INTEGER,
    is_signed       BOOLEAN,
    signer_name     TEXT,
    status          VARCHAR(50),
    threat_event_id UUID REFERENCES threat_events(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_proc_captured_at ON processes_snapshot(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_proc_pid         ON processes_snapshot(pid);
CREATE INDEX IF NOT EXISTS idx_proc_name        ON processes_snapshot(name);
CREATE INDEX IF NOT EXISTS idx_proc_threat      ON processes_snapshot(threat_event_id);
COMMENT ON TABLE processes_snapshot IS 'Point-in-time snapshots of running processes with resource metrics.';

-- Add FK from threat_events → processes_snapshot
ALTER TABLE threat_events
    ADD CONSTRAINT fk_threat_process
    FOREIGN KEY (process_id) REFERENCES processes_snapshot(id) ON DELETE SET NULL;

-- ─────────────────────────────────────────────────────────────
--  NETWORK CONNECTIONS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    bytes_recv      BIGINT NOT NULL DEFAULT 0,
    packet_count    INTEGER NOT NULL DEFAULT 0,
    pid             INTEGER,
    process_name    VARCHAR(255),
    status          VARCHAR(50),
    is_suspicious   BOOLEAN NOT NULL DEFAULT FALSE,
    intel_score     NUMERIC(5,2),        -- AbuseIPDB confidence score 0-100
    threat_event_id UUID REFERENCES threat_events(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_net_captured_at  ON network_connections(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_dst_ip       ON network_connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_net_suspicious   ON network_connections(is_suspicious)
    WHERE is_suspicious = TRUE;
COMMENT ON TABLE network_connections IS 'Active network connections with threat-intel enrichment.';

-- Add FK from threat_events → network_connections
ALTER TABLE threat_events
    ADD CONSTRAINT fk_threat_network
    FOREIGN KEY (network_id) REFERENCES network_connections(id) ON DELETE SET NULL;

-- ─────────────────────────────────────────────────────────────
--  RESPONSE ACTIONS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action_type     VARCHAR(50) NOT NULL
                      CHECK (action_type IN ('kill_process', 'block_ip', 'alert')),
    threat_event_id UUID REFERENCES threat_events(id) ON DELETE SET NULL,
    target_pid      INTEGER,
    target_ip       INET,
    firewall_rule   TEXT,               -- Rule name for rollback
    actor           VARCHAR(255) NOT NULL,
    status          VARCHAR(30) NOT NULL
                      CHECK (status IN ('success', 'failed', 'skipped_protected', 'pending_confirmation')),
    failure_reason  TEXT,
    rolled_back     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_resp_executed ON response_actions(executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_resp_threat   ON response_actions(threat_event_id);
COMMENT ON TABLE response_actions IS 'Audit record of every automated and manual response action.';

-- ─────────────────────────────────────────────────────────────
--  RESPONSE RULES
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_rules (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL,
    threat_level       VARCHAR(20) NOT NULL
                         CHECK (threat_level IN ('Suspicious', 'Critical')),
    action             VARCHAR(50) NOT NULL
                         CHECK (action IN ('kill_process', 'block_ip', 'alert')),
    auto_execute       BOOLEAN NOT NULL DEFAULT FALSE,
    protected_override BOOLEAN NOT NULL DEFAULT FALSE,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE response_rules IS 'Configurable auto-response rules evaluated per threat event.';

-- ─────────────────────────────────────────────────────────────
--  AUDIT LOG
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    logged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT,
    payload     JSONB,
    ip_address  INET,
    outcome     VARCHAR(20) NOT NULL
                  CHECK (outcome IN ('success', 'failed', 'denied'))
);
CREATE INDEX IF NOT EXISTS idx_audit_logged ON audit_log(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor);
COMMENT ON TABLE audit_log IS 'Unified compliance-ready audit trail for all API actions.';

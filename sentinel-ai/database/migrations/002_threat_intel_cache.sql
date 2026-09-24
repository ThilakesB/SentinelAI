-- ============================================================
--  Migration 002: Threat Intel Cache (Supabase side)
--  For high-volume queries — local SQLite is primary cache;
--  this table stores feed metadata and sync history.
-- ============================================================

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    cache_key   TEXT PRIMARY KEY,
    intel_type  VARCHAR(30) NOT NULL,
    data_json   JSONB NOT NULL,
    source      VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ti_cache_expires ON threat_intel_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_ti_cache_type    ON threat_intel_cache(intel_type);
COMMENT ON TABLE threat_intel_cache IS 'Threat intelligence lookup cache synced from external feeds.';

-- Feed sync history
CREATE TABLE IF NOT EXISTS threat_intel_sync_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    feed_name     VARCHAR(50) NOT NULL,
    status        VARCHAR(20) NOT NULL CHECK (status IN ('success', 'failed', 'partial')),
    records_added INTEGER DEFAULT 0,
    error_msg     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sync_log_feed ON threat_intel_sync_log(feed_name, synced_at DESC);
COMMENT ON TABLE threat_intel_sync_log IS 'Audit log of every threat intel feed refresh cycle.';

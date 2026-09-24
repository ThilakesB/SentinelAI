-- ============================================================
--  Migration 003: Audit Log Extensions
--  Adds full-text search index on audit_log for /api/logs/search
-- ============================================================

-- GIN index for JSONB payload search
CREATE INDEX IF NOT EXISTS idx_audit_payload_gin
    ON audit_log USING GIN (payload);

-- Composite index for common filter: actor + date range
CREATE INDEX IF NOT EXISTS idx_audit_actor_date
    ON audit_log(actor, logged_at DESC);

-- Full-text search on action + resource
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS
    search_vector TSVECTOR
    GENERATED ALWAYS AS (
        to_tsvector('english', coalesce(action, '') || ' ' || coalesce(resource, ''))
    ) STORED;
CREATE INDEX IF NOT EXISTS idx_audit_fts ON audit_log USING GIN (search_vector);

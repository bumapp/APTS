-- APTS database schema.
--
-- Matches Characterization §3.1 (Contents) and §3.2 (Access discipline).
-- Every table is written by exactly the components the doc allows, enforced
-- at the SQL layer with per-component GRANTs (see grants.sql — TODO).

-- =========================================================================
--  engagements — one row per test run
-- =========================================================================
CREATE TABLE IF NOT EXISTS engagements (
    id           UUID        PRIMARY KEY,
    target_url   TEXT        NOT NULL,
    scope        JSONB       NOT NULL,
    time_window  JSONB       NOT NULL DEFAULT '{}',
    status       VARCHAR(32) NOT NULL DEFAULT 'created',
        -- created | running | complete | failed
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS engagements_status_idx ON engagements (status);
CREATE INDEX IF NOT EXISTS engagements_created_at_idx ON engagements (created_at DESC);


-- =========================================================================
--  agent_results — one row per (engagement, agent) pair
-- =========================================================================
CREATE TABLE IF NOT EXISTS agent_results (
    id            BIGSERIAL   PRIMARY KEY,
    engagement_id UUID        NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    agent         VARCHAR(32) NOT NULL,
        -- recon | vuln | mitre | exploit | script | adviser
    payload       JSONB       NOT NULL,
    written_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (engagement_id, agent)
);

CREATE INDEX IF NOT EXISTS agent_results_engagement_idx
    ON agent_results (engagement_id);


-- =========================================================================
--  audit_log — append-only history of every event in the system
-- =========================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL   PRIMARY KEY,
    engagement_id  UUID,
        -- nullable: startup / shutdown / global auth failures have no engagement
    component      VARCHAR(64) NOT NULL,
    event_type     VARCHAR(64) NOT NULL,
    detail         JSONB       NOT NULL DEFAULT '{}',
    logged_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_log_engagement_idx  ON audit_log (engagement_id);
CREATE INDEX IF NOT EXISTS audit_log_component_idx   ON audit_log (component);
CREATE INDEX IF NOT EXISTS audit_log_logged_at_idx   ON audit_log (logged_at DESC);


-- =========================================================================
--  token_hashes — salted SHA-256 of each component's bearer token
-- =========================================================================
CREATE TABLE IF NOT EXISTS token_hashes (
    component  VARCHAR(64) PRIMARY KEY,
    salt       BYTEA       NOT NULL,
    digest     BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================================
--  engagement_state — per-agent task state for the retry logic
-- =========================================================================
CREATE TABLE IF NOT EXISTS engagement_state (
    engagement_id UUID        NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    agent         VARCHAR(32) NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'pending',
        -- pending | started | in_progress | done | failed
    retry_count   INT         NOT NULL DEFAULT 0,
    last_error    TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (engagement_id, agent)
);

CREATE INDEX IF NOT EXISTS engagement_state_status_idx
    ON engagement_state (status);

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
--  recon_requests — one row per HTTP request the recon crawler actually
--  observed, exploded out of the recon AssetMap so a request can be looked up
--  precisely by its endpoint path.
--
--  The same data lives inside agent_results.payload->'observed_requests' as a
--  JSON array; this table is the *indexed* projection of it. Populated eagerly
--  by the recon pipeline when it persists its result (see
--  agent/repositories/recon_request_repository.py), never from the crawl cache.
--  The btree on (engagement_id, path) is what makes "fetch the request for
--  endpoint /rest/user/login" an exact index lookup rather than a blob scan.
-- =========================================================================
CREATE TABLE IF NOT EXISTS recon_requests (
    id            BIGSERIAL   PRIMARY KEY,
    engagement_id UUID        NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    seq           INT         NOT NULL DEFAULT 0,
        -- order the request was observed in during the crawl
    method        VARCHAR(8)  NOT NULL DEFAULT 'GET',
    url           TEXT        NOT NULL,
        -- the full observed URL, query string included
    path          TEXT        NOT NULL,
        -- normalised path (no scheme/host/query) — the lookup key
    source_page   TEXT        NOT NULL DEFAULT '',
        -- the page that fired the request (its Referer), '' if none
    content_type  TEXT        NOT NULL DEFAULT '',
    resource_type VARCHAR(32) NOT NULL DEFAULT '',
        -- xhr | fetch | document | ... (Playwright resource type)
    headers       JSONB       NOT NULL DEFAULT '{}',
    post_data     TEXT,
        -- request body, if any (e.g. a login POST payload)
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS recon_requests_engagement_path_idx
    ON recon_requests (engagement_id, path);
CREATE INDEX IF NOT EXISTS recon_requests_path_idx
    ON recon_requests (path);


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
--  agent_trace — the narrative of a run: what each stage was given, every
--  model call and tool call it made, and what it produced
-- =========================================================================
--  Deliberately separate from audit_log. That table is the security trail —
--  who called what, and which Guardrails decision followed (§8) — and it is
--  small, uniform, and worth keeping forever. This one carries prompts and
--  response bodies, is an order of magnitude larger, and exists to answer
--  "why did the report say that?". Mixing the two would make the compliance
--  log unreadable and the debugging log unquotable.
--
--  Ordering is by `id`, not `seq`: BIGSERIAL is monotonic across every agent
--  writing concurrently, whereas `seq` only orders events within one stage
--  run (and is 0 for orchestrator-level events, which have no stage).
CREATE TABLE IF NOT EXISTS agent_trace (
    id            BIGSERIAL   PRIMARY KEY,
    engagement_id UUID        NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    agent         VARCHAR(32) NOT NULL,
        -- a chain stage, or 'orchestrator' for request/retry/completion events
    seq           INT         NOT NULL DEFAULT 0,
        -- ordinal within this stage run; 0 for orchestrator events
    event_type    VARCHAR(32) NOT NULL,
        -- engagement_requested | kickoff | stage_input | llm_call | tool_call
        -- | stage_output | handoff | stage_failed | retry_launched
        -- | report_written | engagement_complete | engagement_failed
    payload       JSONB       NOT NULL DEFAULT '{}',
    duration_ms   INT,
        -- nullable: instantaneous events have no duration
    logged_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_trace_engagement_idx
    ON agent_trace (engagement_id, id);
CREATE INDEX IF NOT EXISTS agent_trace_event_type_idx
    ON agent_trace (event_type);


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

-- PhishLens schema v1 (ТЗ §3). Совместимо с SQLite и PostgreSQL (без вендорных типов).
-- Даты хранятся как TEXT в RFC3339 (UTC).

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    settings    TEXT,                       -- JSON: пороги, веса, ретенция
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,              -- user | analyst | admin
    oidc_sub    TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE (org_id, email)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,      -- sha256(key)
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS submissions (
    id            TEXT PRIMARY KEY,         -- ULID
    org_id        TEXT NOT NULL DEFAULT '',
    channel       TEXT NOT NULL,            -- web | api | outlook | gmail | imap | telegram | cli
    submitted_by  TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL,            -- text | eml | msg | image
    received_at   TEXT NOT NULL,
    status        TEXT NOT NULL,            -- analyzed | in_review | confirmed_phish | confirmed_clean | escalated
    reviewed_by   TEXT NOT NULL DEFAULT '',
    from_domain   TEXT NOT NULL DEFAULT '',
    subject       TEXT,                     -- NULL если store_bodies=false
    message_json  TEXT,                     -- ParsedMail (Business, зашифровано AES-GCM, base64) / NULL
    campaign_key  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_org_received ON submissions(org_id, received_at);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_campaign ON submissions(campaign_key);

CREATE TABLE IF NOT EXISTS analyses (
    submission_id        TEXT PRIMARY KEY REFERENCES submissions(id) ON DELETE CASCADE,
    score                INTEGER NOT NULL,
    verdict              TEXT NOT NULL,     -- phishing | suspicious | clean | needs_review
    confidence           REAL NOT NULL,
    attack_type          TEXT NOT NULL,
    brand_json           TEXT,
    llm_json             TEXT,
    recommendations_json TEXT,
    warnings_json        TEXT,
    duration_ms          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);

CREATE TABLE IF NOT EXISTS signals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    signal_id     TEXT NOT NULL,            -- "header.replyto_mismatch"
    category      TEXT NOT NULL,
    weight        INTEGER NOT NULL,
    confidence    REAL NOT NULL,
    evidence      TEXT NOT NULL,
    explanation   TEXT NOT NULL,
    source        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_submission ON signals(submission_id);
CREATE INDEX IF NOT EXISTS idx_signals_signal_id ON signals(signal_id);

CREATE TABLE IF NOT EXISTS brands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      TEXT NOT NULL DEFAULT '',   -- '' = глобальный (из brands.yaml не дублируется)
    name        TEXT NOT NULL,
    domains     TEXT NOT NULL,              -- JSON array
    esp_domains TEXT NOT NULL DEFAULT '[]',
    keywords    TEXT NOT NULL DEFAULT '[]',
    locale      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL DEFAULT '',
    value      TEXT NOT NULL,               -- домен или адрес
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (org_id, value)
);

CREATE TABLE IF NOT EXISTS blocklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL DEFAULT '',
    value      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (org_id, value)
);

CREATE TABLE IF NOT EXISTS reputation_cache (
    key        TEXT PRIMARY KEY,            -- "rdap:example.com", "dnsbl:1.2.3.4"
    value      TEXT NOT NULL,               -- JSON
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,               -- submission.review, list.add, brand.add, apikey.create ...
    target     TEXT NOT NULL DEFAULT '',
    details    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit(org_id, created_at);

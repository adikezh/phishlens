-- Privacy-safe IOC metadata. It contains no message text or PII.
CREATE TABLE IF NOT EXISTS submission_iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    org_id        TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL, -- domain | url | sha256
    value         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (submission_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_submission_iocs_org_created ON submission_iocs(org_id, created_at);

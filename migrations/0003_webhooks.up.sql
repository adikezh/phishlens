-- Org-scoped HMAC webhook subscriptions. secret_cipher is AES-GCM ciphertext;
-- plaintext webhook secrets must never be persisted.
CREATE TABLE IF NOT EXISTS webhooks (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL,
    name           TEXT NOT NULL,
    url            TEXT NOT NULL,
    secret_cipher  TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_webhooks_org_enabled ON webhooks(org_id, enabled);

-- Nano Blocker schema
-- All statements are idempotent so the schema can be re-run safely on startup.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'allowed',   -- allowed | blocked
    method     TEXT NOT NULL DEFAULT 'both',      -- dns | ufw | both
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_ips (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    ip_address    TEXT NOT NULL,
    last_resolved TEXT NOT NULL,
    UNIQUE (domain_id, ip_address)
);

CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    value      TEXT NOT NULL UNIQUE,
    value_type TEXT NOT NULL,            -- domain | ip
    reason     TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    value      TEXT NOT NULL UNIQUE,
    value_type TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_identifier  TEXT NOT NULL DEFAULT '',   -- the IDB-* comment tag
    action           TEXT NOT NULL,
    direction        TEXT NOT NULL,
    source           TEXT NOT NULL DEFAULT '',
    destination      TEXT NOT NULL DEFAULT '',
    port             TEXT NOT NULL DEFAULT '',
    protocol         TEXT NOT NULL DEFAULT '',
    comment          TEXT NOT NULL DEFAULT '',
    origin           TEXT NOT NULL DEFAULT 'app', -- app | manual
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS temporary_blocks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    target_type TEXT NOT NULL,           -- domain | ip
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'    -- active | expired
);

CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL DEFAULT 'system',
    category   TEXT NOT NULL DEFAULT 'system',    -- domain|firewall|blacklist|whitelist|temporary|auth|dns|error
    event_type TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    message    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'SUCCESS',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_domains_status   ON domains(status);
CREATE INDEX IF NOT EXISTS idx_domain_ips_dom   ON domain_ips(domain_id);
CREATE INDEX IF NOT EXISTS idx_blacklist_value  ON blacklist(value);
CREATE INDEX IF NOT EXISTS idx_whitelist_value  ON whitelist(value);
CREATE INDEX IF NOT EXISTS idx_tmp_status       ON temporary_blocks(status);
CREATE INDEX IF NOT EXISTS idx_logs_category    ON logs(category);
CREATE INDEX IF NOT EXISTS idx_logs_created     ON logs(created_at);

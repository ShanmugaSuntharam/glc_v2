-- glc_v1 audit log. Append-only; the application layer never issues
-- UPDATE or DELETE against this table.
--
-- v2 (Session 12, finding B2 / leak 2): the application layer only ever
-- offered append(), but the SQLite file itself is writable by any code in
-- the gateway process, so `DELETE FROM audit_log` silently erased the
-- security history. The log is now a hash chain: every row carries the hash
-- of the previous row, so a modification or a mid-log deletion breaks the
-- chain, and audit_chain_head anchors the expected head + row count so a
-- wholesale wipe or truncation is caught too. See glc/audit/store.py.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT,
    row_hash        TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- B2 anchor. One row (id=1) recording the chain head and how many chained
-- rows should exist. Without this, an empty table would verify vacuously and
-- `DELETE FROM audit_log` would go unnoticed.
CREATE TABLE IF NOT EXISTS audit_chain_head (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    head_hash  TEXT    NOT NULL,
    row_count  INTEGER NOT NULL,
    updated_at REAL    NOT NULL
);
INSERT OR IGNORE INTO audit_chain_head (id, head_hash, row_count, updated_at)
VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000', 0, strftime('%s','now'));

-- Schema version table: any change to the columns above requires a
-- documented version bump. Migrations are not automatic -- see
-- glc/audit/store.py::_migrate, which ALTERs a v1 audit_log up to v2 by
-- adding prev_hash/row_hash (existing v1 rows stay unchained and are
-- reported as `legacy_rows` by verify_chain()).
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (2, strftime('%s','now'));

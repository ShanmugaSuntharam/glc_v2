"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
ships with `audit_schema` version 1; bumping it requires a documented
migration step (see schema.sql).

Each append commits immediately (SQLite autocommit) so writes survive a
hard kill. Finding A6: under Modal the db lives on a Volume whose writes
only become durable on volume.commit(); modal_app.py registers that commit
via set_commit_hook() so each append is flushed all the way to the Volume.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

# ────────────────────────────────────────────────────────────────────────────
# Finding B2 (leak 2) — the audit db is writable at the OS layer
# ────────────────────────────────────────────────────────────────────────────
# append() is the only writer the application layer offers, but the SQLite
# file has no enforcement beyond filesystem permissions, which in-process code
# passes trivially:
#
#     sqlite3.connect("~/.glc/audit.sqlite").execute("DELETE FROM audit_log")
#
# ...and the security history is gone, silently. Invariant 7 says a component
# must not be able to erase or rewrite its own audit log.
#
# The log is therefore a HASH CHAIN. Each row stores prev_hash (the previous
# row's hash) and row_hash = sha256(prev_hash + this row's fields), and
# audit_chain_head anchors the expected head hash + row count. verify_chain()
# recomputes the whole chain and catches:
#   * a modified row      -> recomputed hash != stored row_hash
#   * a deleted mid row   -> the next row's prev_hash no longer links
#   * a truncation / wipe -> surviving row count != the anchored row_count
#                            (this is what catches `DELETE FROM audit_log`,
#                            which an in-table chain alone would miss, since
#                            an empty table chains vacuously)
#   * a dropped table     -> reported rather than raising
#
# Honest scope: this makes tampering DETECTABLE, not impossible. The hash is
# unkeyed and the anchor lives in the same file, so code in the gateway
# process can still delete rows AND recompute the chain + anchor to match.
# What it closes is the naive erase the finding names, and it makes any
# tampering that does not also forge the chain loudly visible. Tamper-PROOF
# needs the writer in its own process holding a key the caller cannot reach,
# or an external anchor -- same root cause as B5/B6 (one process, no walls).

# The chain's fixed starting point, before any row exists.
GENESIS_HASH = "0" * 64

# Finding A6: the audit db lives on a Modal Volume, and a write to a Volume
# mount is not durable until the Volume is committed. modal_app.py registers
# data_volume.commit here so every append persists past container shutdown /
# scale-to-zero. Unset locally and in tests (SQLite autocommit alone is
# durable on a normal filesystem), so this stays a no-op off Modal.
_commit_hook: Callable[[], None] | None = None


def set_commit_hook(fn: Callable[[], None] | None) -> None:
    global _commit_hook
    _commit_hook = fn


def _run_commit_hook() -> None:
    if _commit_hook is None:
        return
    try:
        _commit_hook()
    except Exception:
        # A volume-commit hiccup must never fail the request path or, worse,
        # become a way to block auditing. SQLite has already flushed the row
        # to the container's view of the Volume; Modal's background commit is
        # the backstop. Swallow and move on.
        pass


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# B2: serialises the read-head / insert / advance-head sequence in append().
# A6 caps the deployment at one container, so one process-wide lock is the
# whole story; without it two concurrent appends could read the same head and
# fork the chain.
_append_lock = threading.Lock()


def _migrate(c: sqlite3.Connection) -> None:
    """v1 -> v2 (finding B2): add the chain columns to a pre-existing
    audit_log. CREATE TABLE IF NOT EXISTS in schema.sql cannot add columns to
    a table that already exists, so ALTER explicitly. Rows written before the
    migration keep NULL hashes and are reported as `legacy_rows` by
    verify_chain() -- they cannot be retroactively chained honestly."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_log)").fetchall()}
    for col in ("prev_hash", "row_hash"):
        if col not in cols:
            c.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT")


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        _migrate(c)


def _row_digest(
    prev_hash: str,
    ts: float,
    session_id: str | None,
    channel: str,
    channel_user_id: str,
    trust_level: str,
    event_type: str,
    tool: str | None,
    policy_verdict: str | None,
    params_json: str | None,
    result_json: str | None,
) -> str:
    """sha256 over the previous hash plus every stored field of this row, so
    changing any one of them (or the row's position) changes the hash. `id` is
    excluded because it is only known after INSERT; ordering is already
    pinned by prev_hash linking each row to its predecessor."""
    payload = json.dumps(
        [
            prev_hash,
            ts,
            session_id,
            channel,
            channel_user_id,
            trust_level,
            event_type,
            tool,
            policy_verdict,
            params_json,
            result_json,
        ],
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        ts = time.time()
        params_json = _jsonify(params)
        result_json = _jsonify(result)

        # B2: read head -> insert chained row -> advance head, atomically, so
        # the anchor can never drift from the table.
        with _append_lock, _conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                head = c.execute(
                    "SELECT head_hash, row_count FROM audit_chain_head WHERE id=1"
                ).fetchone()
                prev_hash = head["head_hash"] if head else GENESIS_HASH
                count = int(head["row_count"]) if head else 0

                row_hash = _row_digest(
                    prev_hash,
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                )
                cur = c.execute(
                    """INSERT INTO audit_log
                       (ts, session_id, channel, channel_user_id, trust_level,
                        event_type, tool, policy_verdict, params_json, result_json,
                        prev_hash, row_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ts,
                        session_id,
                        channel,
                        channel_user_id,
                        trust_level,
                        event_type,
                        tool,
                        policy_verdict,
                        params_json,
                        result_json,
                        prev_hash,
                        row_hash,
                    ),
                )
                rowid = int(cur.lastrowid or 0)
                c.execute(
                    """INSERT INTO audit_chain_head (id, head_hash, row_count, updated_at)
                       VALUES (1,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET
                         head_hash=excluded.head_hash,
                         row_count=excluded.row_count,
                         updated_at=excluded.updated_at""",
                    (row_hash, count + 1, ts),
                )
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        # A6: flush the row all the way to the Modal Volume (no-op off Modal).
        _run_commit_hook()
        return rowid


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)


def verify_chain() -> dict:
    """Finding B2: recompute the hash chain and compare it to the anchor.

    Returns a dict with:
      ok           -- True if the log is intact
      rows         -- number of chained rows walked
      legacy_rows  -- pre-v2 rows with no hash (unverifiable, not a failure)
      head         -- the computed head hash
      reason       -- why it failed, when ok is False:
                        table_missing  -- audit_log/anchor dropped
                        chain_broken   -- a row's prev_hash does not link
                        row_modified   -- a row's contents no longer hash
                        rows_missing   -- fewer rows than the anchor expects
                                          (a DELETE / truncation)
                        head_mismatch  -- final hash != anchored head
      broken_at    -- audit_log.id where it first went wrong, if applicable
    """
    try:
        with _conn() as c:
            head = c.execute("SELECT head_hash, row_count FROM audit_chain_head WHERE id=1").fetchone()
            rows = c.execute(
                "SELECT * FROM audit_log WHERE row_hash IS NOT NULL ORDER BY id"
            ).fetchall()
            legacy = int(
                c.execute("SELECT COUNT(*) AS n FROM audit_log WHERE row_hash IS NULL").fetchone()["n"]
            )
    except sqlite3.OperationalError as e:
        # DROP TABLE audit_log / audit_chain_head lands here.
        return {"ok": False, "reason": "table_missing", "detail": str(e), "rows": 0, "legacy_rows": 0}

    expected_prev = GENESIS_HASH
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {
                "ok": False,
                "reason": "chain_broken",
                "broken_at": r["id"],
                "rows": len(rows),
                "legacy_rows": legacy,
            }
        recomputed = _row_digest(
            r["prev_hash"],
            r["ts"],
            r["session_id"],
            r["channel"],
            r["channel_user_id"],
            r["trust_level"],
            r["event_type"],
            r["tool"],
            r["policy_verdict"],
            r["params_json"],
            r["result_json"],
        )
        if recomputed != r["row_hash"]:
            return {
                "ok": False,
                "reason": "row_modified",
                "broken_at": r["id"],
                "rows": len(rows),
                "legacy_rows": legacy,
            }
        expected_prev = r["row_hash"]

    if head is None:
        return {"ok": False, "reason": "table_missing", "rows": len(rows), "legacy_rows": legacy}

    # The anchor is what catches a wholesale `DELETE FROM audit_log`: the rows
    # are gone, but the head still remembers how many there should have been.
    if len(rows) != int(head["row_count"]):
        return {
            "ok": False,
            "reason": "rows_missing",
            "expected_rows": int(head["row_count"]),
            "rows": len(rows),
            "legacy_rows": legacy,
        }
    if expected_prev != head["head_hash"]:
        return {"ok": False, "reason": "head_mismatch", "rows": len(rows), "legacy_rows": legacy}

    return {"ok": True, "rows": len(rows), "legacy_rows": legacy, "head": expected_prev}

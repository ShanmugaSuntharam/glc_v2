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

import json
import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))

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


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())


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
        with _conn() as c:
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    time.time(),
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    _jsonify(params),
                    _jsonify(result),
                ),
            )
            rowid = int(cur.lastrowid or 0)
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

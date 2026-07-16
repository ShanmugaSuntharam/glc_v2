"""V9-compatible per-call ledger. Same schema as llm_gatewayV9/db.py, but
the database lives under ~/.glc/ so the gateway is installable as a daemon
without writing into the source tree.

Note: this is the *worker call* ledger, used by /v1/cost/by_agent. The
audit log (every channel message, policy verdict, tool dispatch) is a
separate append-only store under glc/audit/store.py.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
DB_PATH = os.getenv("GLC_GATEWAY_DB", str(DEFAULT_DIR / "gateway.sqlite"))

# ────────────────────────────────────────────────────────────────────────────
# Finding B7 — cost-ledger poisoning
# ────────────────────────────────────────────────────────────────────────────
# log_call() used to write whatever the caller handed it, validating nothing,
# so any code sharing the gateway process could poison the ledger that
# /v1/cost/by_agent, recent() and aggregate() report from:
#
#     glc.db.log_call(provider="gemini", model="x",
#                     input_tokens=999_999_999, agent="victim", status="ok")
#
# Three concrete harms, all closed below by validating at this one chokepoint:
#   * absurd counters inflate spend/usage (the notes' exploit above);
#   * NEGATIVE counters are worse -- they shrink the SUM() in by_agent() and
#     aggregate(), so an attacker can mask real spend rather than just fake it;
#   * a non-int slides straight into an INTEGER column, because SQLite is
#     dynamically typed, corrupting every later SUM/AVG over that column.
# Text fields are length-bounded so a caller cannot fill the ledger with giant
# blobs (a cheap denial-of-service / disk-fill on the same Volume).
#
# Honest scope: this does NOT stop a caller writing *plausible* fake rows, or
# attributing a real call to another agent -- the numbers would pass every
# check here. That needs a signed writer the gateway alone holds, plus process
# separation, and stays capstone scope (see docs/SECURITY_FIXES.md).

# Ceilings sit far above any real call, so a legitimate row can never trip
# them: the largest production context windows are ~2M tokens, and a call
# cannot plausibly run for a day.
MAX_TOKENS = 10_000_000
MAX_CHARS = 100_000_000
MAX_LATENCY_MS = 86_400_000  # 24h
MAX_TOOL_CALLS = 10_000
MAX_RETRIES = 1_000
MAX_EMBED_DIM = 100_000
MAX_TEXT_LEN = 4096


class LedgerValueError(ValueError):
    """A ledger field failed validation — the row is refused, not written."""


def _counter(name: str, value: Any, ceiling: int, *, nullable: bool = False) -> int | None:
    """Validate one numeric ledger column: a non-negative whole number within
    `ceiling`. None means 'not supplied' -> 0 (or NULL for nullable columns)."""
    if value is None:
        return None if nullable else 0
    # bool is an int subclass; a True/False counter is always a caller bug.
    if isinstance(value, bool):
        raise LedgerValueError(f"{name} must be an integer, got bool")
    if isinstance(value, float):
        if not value.is_integer():
            raise LedgerValueError(f"{name} must be a whole number, got {value!r}")
        value = int(value)
    if not isinstance(value, int):
        raise LedgerValueError(f"{name} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise LedgerValueError(f"{name} must be >= 0, got {value}")
    if value > ceiling:
        raise LedgerValueError(f"{name}={value} exceeds the plausible ceiling {ceiling}")
    return value


def _text(name: str, value: Any, *, required: bool = False) -> str | None:
    """Validate one text ledger column: a string, length-bounded."""
    if value is None:
        if required:
            raise LedgerValueError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise LedgerValueError(f"{name} must be a string, got {type(value).__name__}")
    if required and not value.strip():
        raise LedgerValueError(f"{name} must not be empty")
    return value[:MAX_TEXT_LEN]


def _ensure_parent() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def conn():
    _ensure_parent()
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> None:
    with conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                cache_create_tokens INTEGER DEFAULT 0,
                cache_read_tokens INTEGER DEFAULT 0,
                latency_ms INTEGER DEFAULT 0,
                status TEXT,
                error TEXT,
                prompt_chars INTEGER DEFAULT 0,
                response_chars INTEGER DEFAULT 0,
                override TEXT,
                attempted TEXT,
                tool_calls INTEGER DEFAULT 0,
                reasoning_applied INTEGER DEFAULT 0,
                tool_dialect TEXT,
                call_role TEXT DEFAULT 'worker',
                router_decision TEXT,
                embed_dim INTEGER,
                agent TEXT,
                session TEXT,
                retries INTEGER DEFAULT 0
            )"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON calls(ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts ON calls(provider, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_role_ts ON calls(call_role, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_agent_ts ON calls(agent, ts DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_session_ts ON calls(session, ts DESC)")


def log_call(
    provider,
    model,
    input_tokens=0,
    output_tokens=0,
    latency_ms=0,
    status="ok",
    error=None,
    prompt_chars=0,
    response_chars=0,
    override=None,
    attempted=None,
    cache_create_tokens=0,
    cache_read_tokens=0,
    tool_calls=0,
    reasoning_applied=False,
    tool_dialect=None,
    call_role="worker",
    router_decision=None,
    embed_dim=None,
    agent=None,
    session=None,
    retries=0,
) -> None:
    # B7: validate every field before it reaches the ledger. A poisoned row is
    # refused outright rather than clamped -- clamping would still record the
    # attacker's fiction, just a smaller one.
    provider = _text("provider", provider, required=True)
    model = _text("model", model, required=True)
    input_tokens = _counter("input_tokens", input_tokens, MAX_TOKENS)
    output_tokens = _counter("output_tokens", output_tokens, MAX_TOKENS)
    cache_create_tokens = _counter("cache_create_tokens", cache_create_tokens, MAX_TOKENS)
    cache_read_tokens = _counter("cache_read_tokens", cache_read_tokens, MAX_TOKENS)
    latency_ms = _counter("latency_ms", latency_ms, MAX_LATENCY_MS)
    prompt_chars = _counter("prompt_chars", prompt_chars, MAX_CHARS)
    response_chars = _counter("response_chars", response_chars, MAX_CHARS)
    tool_calls = _counter("tool_calls", tool_calls, MAX_TOOL_CALLS)
    retries = _counter("retries", retries, MAX_RETRIES)
    embed_dim = _counter("embed_dim", embed_dim, MAX_EMBED_DIM, nullable=True)
    status = _text("status", status)
    error = _text("error", error)
    override = _text("override", override)
    attempted = _text("attempted", attempted)
    tool_dialect = _text("tool_dialect", tool_dialect)
    call_role = _text("call_role", call_role)
    router_decision = _text("router_decision", router_decision)
    agent = _text("agent", agent)
    session = _text("session", session)

    with conn() as c:
        c.execute(
            """INSERT INTO calls (ts, provider, model, input_tokens, output_tokens,
                                  cache_create_tokens, cache_read_tokens,
                                  latency_ms, status, error, prompt_chars, response_chars,
                                  override, attempted, tool_calls, reasoning_applied, tool_dialect,
                                  call_role, router_decision, embed_dim,
                                  agent, session, retries)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                provider,
                model,
                input_tokens,
                output_tokens,
                cache_create_tokens,
                cache_read_tokens,
                latency_ms,
                status,
                error,
                prompt_chars,
                response_chars,
                override,
                attempted,
                tool_calls,
                1 if reasoning_applied else 0,
                tool_dialect,
                call_role,
                router_decision,
                embed_dim,
                agent,
                session,
                retries,
            ),
        )


def by_agent(session=None, since=None):
    where = ["ts >= ?"]
    # Day-rollover fix: bucket by calendar day, not by 24h window.
    args = [since if since is not None else (time.time() - (time.time() % 86400))]
    if session:
        where.append("session=?")
        args.append(session)
    q = (
        "SELECT agent, provider, COUNT(*) AS calls, "
        "SUM(input_tokens) AS in_tok, SUM(output_tokens) AS out_tok, "
        "SUM(latency_ms) AS total_latency_ms, "
        "SUM(retries) AS total_retries, "
        "SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok, "
        "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors "
        "FROM calls WHERE " + " AND ".join(where) + " AND agent IS NOT NULL "
        "GROUP BY agent, provider"
    )
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        out: dict[str, list[dict]] = {}
        for r in rows:
            out.setdefault(r["agent"], []).append(dict(r))
        return out


def recent(limit=100, provider=None, status=None):
    q = "SELECT * FROM calls"
    where, args = [], []
    if provider:
        where.append("provider=?")
        args.append(provider)
    if status:
        where.append("status=?")
        args.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def aggregate(call_role=None):
    now = time.time()
    day_start = now - (now % 86400)
    q = """SELECT provider,
                  COUNT(*) AS calls,
                  SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) AS ok_calls,
                  SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
                  SUM(input_tokens) AS in_tok,
                  SUM(output_tokens) AS out_tok,
                  SUM(cache_read_tokens) AS cache_reads,
                  SUM(cache_create_tokens) AS cache_creates,
                  SUM(tool_calls) AS tool_calls,
                  AVG(latency_ms) AS avg_latency,
                  MAX(ts) AS last_ts
             FROM calls WHERE ts >= ?"""
    args = [day_start]
    if call_role == "worker":
        q += " AND (call_role='worker' OR call_role IS NULL)"
    elif call_role == "router":
        q += " AND call_role LIKE 'router%'"
    elif call_role:
        q += " AND call_role=?"
        args.append(call_role)
    q += " GROUP BY provider"
    with conn() as c:
        rows = c.execute(q, args).fetchall()
        return {r["provider"]: dict(r) for r in rows}

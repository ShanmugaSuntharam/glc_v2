"""Session 12, finding C5 — no rate limits or budget on the public data plane.

There was a RateLimiter, but it only ever guarded the CHANNEL path
(glc/security/rate_limits.py, keyed on channel + channel_user_id). The data
plane -- /v1/chat, /chat/batch, /vision, /embed, /speak, /transcribe -- had
neither a rate limit nor a spend cap. Anyone holding the install token could
loop on /v1/chat and the gateway would faithfully relay every call to a paid
provider until the account was drained. That is denial-of-service and
denial-of-wallet on a shared account, and it breaks invariant 8: "every run
must have hard limits on time, tokens, tool calls, and cost."

Three limits, because they stop different things:

  * PER-CALLER rate limit (keyed on client IP): stops one noisy client.
  * GLOBAL rate limit: the data plane has exactly one credential, so every
    caller is the same principal to us. A per-IP limit alone is evaded by
    rotating IPs; the global cap is what actually protects the account.
  * DAILY BUDGET, in dollars: the one that matters. Rate limits bound the
    *rate* of spend, not the *total* -- a slow attacker under every rate limit
    still empties the account, just politely. The budget is computed from the
    cost ledger (glc/db.py) priced through glc/pricing.py, and is checked
    BEFORE the provider call, so the cap is a wall rather than a report.

Honest scope: the budget reads the ledger B7 hardened, so it is exactly as
trustworthy as that -- in-gateway code that can forge ledger rows can also
make the gateway believe it has spent nothing. Costs are ESTIMATED from token
counts via pricing.py, not reconciled against provider invoices, so the cap is
approximate. And the per-IP key trusts request.client.host, which behind a
proxy may be the proxy: the global cap is the backstop for exactly that.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque

# Deliberately generous defaults: this is a safety net against a runaway loop
# or a hostile caller, not a product quota. Operators tune it per deployment.
DEFAULT_PER_CALLER_RPM = 60
DEFAULT_GLOBAL_RPM = 240
DEFAULT_DAILY_BUDGET_USD = 10.0

PER_CALLER_RPM_ENV = "GLC_DATA_PLANE_RPM"
GLOBAL_RPM_ENV = "GLC_DATA_PLANE_GLOBAL_RPM"
DAILY_BUDGET_ENV = "GLC_DAILY_BUDGET_USD"

_lock = threading.Lock()
_per_caller: dict[str, deque[float]] = {}
_global: deque[float] = deque()


class QuotaExceeded(Exception):
    """A limit was hit. The caller gets a 429; nothing reaches a provider."""


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _gc(dq: deque[float], horizon: float) -> None:
    while dq and dq[0] < horizon:
        dq.popleft()


def reset() -> None:
    """Drop all windows. For tests, and for a deliberate operator reset."""
    with _lock:
        _per_caller.clear()
        _global.clear()


def spend_today_usd() -> float:
    """What this installation has spent today, per the cost ledger, priced
    through pricing.py. Estimated from token counts -- not an invoice."""
    from glc import db, pricing

    total = 0.0
    try:
        for provider, row in db.aggregate().items():
            total += pricing.estimate_usd(
                provider, int(row.get("in_tok") or 0), int(row.get("out_tok") or 0)
            )
    except Exception:
        # A ledger read must never take the data plane down; the rate limits
        # still apply.
        return 0.0
    return total


def check_budget() -> tuple[bool, str]:
    """The hard cost cap (invariant 8). Checked before the provider call."""
    cap = _float_env(DAILY_BUDGET_ENV, DEFAULT_DAILY_BUDGET_USD)
    if cap <= 0:
        return True, ""  # explicitly disabled
    spent = spend_today_usd()
    if spent >= cap:
        return False, f"daily budget of ${cap:.2f} is exhausted (spent ~${spent:.2f} today)"
    return True, ""


def check_rate(caller: str) -> tuple[bool, str]:
    per_caller_cap = _int_env(PER_CALLER_RPM_ENV, DEFAULT_PER_CALLER_RPM)
    global_cap = _int_env(GLOBAL_RPM_ENV, DEFAULT_GLOBAL_RPM)
    now = time.time()
    horizon = now - 60
    with _lock:
        _gc(_global, horizon)
        if global_cap > 0 and len(_global) >= global_cap:
            return False, f"data plane is over its global limit of {global_cap} requests/min"

        dq = _per_caller.setdefault(caller, deque())
        _gc(dq, horizon)
        if per_caller_cap > 0 and len(dq) >= per_caller_cap:
            return False, f"caller is over the limit of {per_caller_cap} requests/min"

        dq.append(now)
        _global.append(now)
        return True, ""


def enforce(endpoint: str, caller: str, *, agent: str | None = None) -> None:
    """Gate one data-plane request. Raises QuotaExceeded; the route turns that
    into a 429. Both limits are audited when they bite, because a client
    hammering the gateway is a security event, not just a noisy one."""
    ok, why = check_rate(caller)
    if not ok:
        _audit("rate_limit_exceeded", endpoint, caller, agent, why)
        raise QuotaExceeded(why)

    ok, why = check_budget()
    if not ok:
        _audit("budget_exhausted", endpoint, caller, agent, why)
        raise QuotaExceeded(why)


def enforce_http(endpoint: str, request, *, agent: str | None = None) -> None:
    """enforce() for a FastAPI route: turns QuotaExceeded into a 429.

    The caller key is request.client.host. Behind a proxy that may be the
    proxy's address rather than the real client -- which is exactly why the
    global cap exists alongside the per-caller one.
    """
    from fastapi import HTTPException

    caller = request.client.host if request.client else "unknown"
    try:
        enforce(endpoint, caller, agent=agent)
    except QuotaExceeded as e:
        raise HTTPException(429, str(e)) from None


def _audit(event_type: str, endpoint: str, caller: str, agent: str | None, why: str) -> None:
    try:
        from glc.audit import append as audit_append

        audit_append(
            channel="_api",
            channel_user_id=caller,
            trust_level="untrusted",
            event_type=event_type,
            params={"endpoint": endpoint, "agent": agent},
            result={"reason": why},
        )
    except Exception:
        pass

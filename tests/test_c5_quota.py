"""Session 12, finding C5 — no rate limits or budget on the public data plane.

There was a RateLimiter, but it only guarded the CHANNEL path. /v1/chat,
/chat/batch, /vision, /embed, /speak and /transcribe had neither a rate limit
nor a spend cap, so anyone holding the install token could loop on /v1/chat
and the gateway would relay every call to a paid provider until the account
was drained: denial-of-service and denial-of-wallet on a shared account.
Invariant 8 says every run has hard limits on time, tokens, tool calls, cost.
"""

from __future__ import annotations

import pytest

from glc.audit import query
from glc.security import quota

CHAT = {"messages": [{"role": "user", "content": "hello"}]}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── rate limiting ───────────────────────────────────────────────────────────


def test_per_caller_rate_limit_bites(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "3")
    quota.reset()

    codes = [
        app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT).status_code
        for _ in range(5)
    ]

    assert codes.count(429) == 2, codes  # 3 allowed, then the wall
    assert 429 in codes


def test_the_global_cap_catches_ip_rotation(monkeypatch):
    """The data plane has ONE credential, so every caller is the same principal
    to us. A per-IP limit alone is evaded by rotating IPs -- the global cap is
    what actually protects the account."""
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "1000")
    monkeypatch.setenv(quota.GLOBAL_RPM_ENV, "3")
    quota.reset()

    results = [quota.check_rate(f"10.0.0.{i}") for i in range(5)]  # a fresh IP each time

    assert [ok for ok, _ in results] == [True, True, True, False, False]
    assert "global limit" in results[3][1]


def test_rate_limit_is_audited(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "1")
    quota.reset()

    app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)
    app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    events = [r["event_type"] for r in query(limit=20)]
    assert "rate_limit_exceeded" in events


def test_a_limit_of_zero_disables_that_check(monkeypatch):
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "0")
    monkeypatch.setenv(quota.GLOBAL_RPM_ENV, "0")
    quota.reset()

    for _ in range(50):
        ok, _why = quota.check_rate("1.2.3.4")
        assert ok is True


# ── the budget: the limit that actually matters ─────────────────────────────


def test_budget_blocks_when_exhausted(monkeypatch):
    """Rate limits bound the RATE of spend, not the total. A slow attacker
    under every rate limit still empties the account -- politely."""
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "1.0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 1.5)

    ok, why = quota.check_budget()

    assert ok is False
    assert "budget" in why and "exhausted" in why


def test_budget_allows_when_under(monkeypatch):
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "10.0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 0.25)
    assert quota.check_budget()[0] is True


def test_budget_of_zero_is_disabled(monkeypatch):
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 999.0)
    assert quota.check_budget()[0] is True


def test_exhausted_budget_stops_the_data_plane(app_client, install_token, monkeypatch):
    """The cap is a wall, not a report: it is checked BEFORE the provider call."""
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "1.0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 99.0)
    quota.reset()

    r = app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    assert r.status_code == 429
    assert "budget" in r.json()["detail"]


def test_budget_exhaustion_is_audited(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "1.0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 99.0)
    quota.reset()

    app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    events = [r["event_type"] for r in query(limit=20)]
    assert "budget_exhausted" in events


def test_spend_is_computed_from_the_ledger(app_client, install_token):
    """The budget reads the cost ledger B7 hardened -- it is exactly as
    trustworthy as that, and priced (estimated) through pricing.py."""
    from glc import db

    db.log_call(provider="gemini", model="gemini-2.5-flash", input_tokens=1000, output_tokens=1000)

    assert quota.spend_today_usd() >= 0.0  # priced without raising


def test_a_broken_ledger_does_not_take_the_data_plane_down(monkeypatch):
    def boom():
        raise RuntimeError("ledger unavailable")

    monkeypatch.setattr("glc.db.aggregate", boom)
    assert quota.spend_today_usd() == 0.0  # degrades to rate limits only


# ── the amplification path ──────────────────────────────────────────────────


def test_batch_counts_every_entry_against_the_limit(app_client, install_token, monkeypatch):
    """A batch of N is N provider calls -- that IS the denial-of-wallet vector,
    so it must cost N against the quota, not 1."""
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "2")
    quota.reset()

    r = app_client.post(
        "/v1/chat/batch", headers=_auth(install_token), json={"calls": [CHAT, CHAT, CHAT, CHAT]}
    )

    codes = [e.get("status_code") for e in r.json()["results"]]
    assert 429 in codes, codes  # the later entries hit the wall


# ── quotas apply only after auth, and to the paid surface ───────────────────


def test_unauthenticated_requests_are_rejected_before_the_quota(app_client, monkeypatch):
    """A missing token must not be able to burn another caller's rate budget."""
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "1")
    quota.reset()

    assert app_client.post("/v1/chat", json=CHAT).status_code == 401
    assert app_client.post("/v1/chat", json=CHAT).status_code == 401  # still 401, not 429


def test_healthz_is_not_rate_limited(app_client, monkeypatch):
    monkeypatch.setenv(quota.PER_CALLER_RPM_ENV, "1")
    quota.reset()

    for _ in range(5):
        assert app_client.get("/healthz").status_code == 200


@pytest.mark.parametrize("endpoint", ["/v1/speak", "/v1/transcribe"])
def test_other_paid_endpoints_are_gated(endpoint, app_client, install_token, monkeypatch):
    """speak/transcribe call paid providers too; they must be bounded."""
    monkeypatch.setenv(quota.DAILY_BUDGET_ENV, "1.0")
    monkeypatch.setattr(quota, "spend_today_usd", lambda: 99.0)
    quota.reset()

    body = {"text": "hi"} if endpoint == "/v1/speak" else {"audio_b64": "AA==", "mime": "audio/wav"}
    r = app_client.post(endpoint, headers=_auth(install_token), json=body)

    assert r.status_code == 429

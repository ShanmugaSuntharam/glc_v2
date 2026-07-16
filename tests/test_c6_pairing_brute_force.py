"""Session 12, finding C6 — pairing-code brute force (listed as a *candidate*).

The notes pose the question directly: "Worth confirming whether any
user-initiated pairing path is reachable without the install token."

ANSWER: no. /v1/control/pair and /v1/control/pair/confirm both call
_require_token, and the only other issue_code/confirm_code callers are setup
scripts running in their own process, not HTTP-reachable. So the brute force
does NOT reproduce as an unauthenticated attack, and a caller who already
holds the install token has no need to guess -- they can issue a code
outright. The tests below pin that answer so it cannot rot.

The underlying weakness is real but LATENT: six digits (1,000,000), a
five-minute TTL, and -- before this fix -- unlimited guesses. The TTL alone
was never protection; it was a deadline an attacker could beat. The moment a
user-initiated pairing path appears (the agent runtime in a later session, a
WebUI flow), it goes live. So the guess cap is added now, which is what makes
a short human-entered code safe in the first place -- exactly as with 2FA.
"""

from __future__ import annotations

from glc.audit import query
from glc.security import quota


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── the notes' open question, pinned ────────────────────────────────────────


def test_pair_confirm_is_not_reachable_without_the_install_token(app_client):
    r = app_client.post("/v1/control/pair/confirm", json={"code": "123456"})
    assert r.status_code == 401


def test_pair_issue_is_not_reachable_without_the_install_token(app_client):
    r = app_client.post(
        "/v1/control/pair",
        json={"channel": "telegram", "channel_user_id": "u1", "user_handle": "u"},
    )
    assert r.status_code == 401


# ── the guess cap: what actually makes a 6-digit code safe ──────────────────


def test_guesses_are_capped(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.PAIR_CONFIRM_RPM_ENV, "3")
    quota.reset()

    codes = [
        app_client.post(
            "/v1/control/pair/confirm", headers=_auth(install_token), json={"code": f"00000{i}"}
        ).status_code
        for i in range(5)
    ]

    assert codes[:3] == [404, 404, 404]  # wrong, but allowed to try
    assert codes[3:] == [429, 429]  # then the wall


def test_the_cap_is_tighter_than_the_data_plane_limit():
    """A pairing guess is not a normal request; 60/min would still allow 300
    tries inside a code's five-minute life."""
    assert quota.DEFAULT_PAIR_CONFIRM_RPM < quota.DEFAULT_PER_CALLER_RPM


def test_rate_limited_guessing_is_audited(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.PAIR_CONFIRM_RPM_ENV, "1")
    quota.reset()

    app_client.post("/v1/control/pair/confirm", headers=_auth(install_token), json={"code": "000001"})
    app_client.post("/v1/control/pair/confirm", headers=_auth(install_token), json={"code": "000002"})

    events = [r["event_type"] for r in query(limit=20)]
    assert "pair_confirm_rate_limited" in events


def test_a_wrong_code_is_audited(app_client, install_token):
    """One wrong code is a typo; a stream of them is a brute force. The audit
    log is where that difference becomes visible."""
    app_client.post("/v1/control/pair/confirm", headers=_auth(install_token), json={"code": "999999"})

    events = [r["event_type"] for r in query(limit=20)]
    assert "pair_confirm_failed" in events


def test_a_cap_of_zero_disables_the_check(monkeypatch):
    monkeypatch.setenv(quota.PAIR_CONFIRM_RPM_ENV, "0")
    quota.reset()
    for _ in range(50):
        assert quota.check_pair_confirm("1.2.3.4")[0] is True


# ── the honest path still works ─────────────────────────────────────────────


def test_the_real_pairing_round_trip_still_works(app_client, install_token):
    """The cap must not break the flow it protects: issue a code, confirm it."""
    quota.reset()
    issued = app_client.post(
        "/v1/control/pair",
        headers=_auth(install_token),
        json={"channel": "telegram", "channel_user_id": "u1", "user_handle": "u"},
    )
    code = issued.json()["code"]

    r = app_client.post("/v1/control/pair/confirm", headers=_auth(install_token), json={"code": code})

    assert r.status_code == 200
    assert r.json()["channel_user_id"] == "u1"
    assert r.json()["trust_level"] == "user_paired"


def test_a_correct_code_still_works_after_some_wrong_ones(app_client, install_token, monkeypatch):
    monkeypatch.setenv(quota.PAIR_CONFIRM_RPM_ENV, "10")
    quota.reset()
    issued = app_client.post(
        "/v1/control/pair",
        headers=_auth(install_token),
        json={"channel": "telegram", "channel_user_id": "u2", "user_handle": "u"},
    )
    code = issued.json()["code"]

    for i in range(3):
        app_client.post(
            "/v1/control/pair/confirm", headers=_auth(install_token), json={"code": f"11111{i}"}
        )

    r = app_client.post("/v1/control/pair/confirm", headers=_auth(install_token), json={"code": code})
    assert r.status_code == 200

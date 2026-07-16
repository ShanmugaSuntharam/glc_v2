"""Session 12, finding C4 — verbose upstream errors.

/v1/chat handed the caller the raw provider exception and the provider name:

    "all providers unavailable. attempts: [...] last_error: <raw upstream error>"

That is free reconnaissance -- it names which providers are configured and in
what order, and the raw error carries the upstream endpoint (this is how the
class notes established the Function could reach googleapis.com), library
versions, and sometimes request URLs with credentials in them.

The caller now gets a generic message plus a correlation ref; the detail goes
to the audit log.
"""

from __future__ import annotations

import json

from glc.audit import query

# No provider keys are configured in the suite, so every provider path fails --
# which is exactly the "all providers unavailable" branch this finding is about.
CHAT = {"messages": [{"role": "user", "content": "hello"}]}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── the client is told nothing useful to an attacker ────────────────────────


def test_chat_error_does_not_name_providers_or_endpoints(app_client, install_token):
    r = app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    assert r.status_code == 503
    body = r.text.lower()
    for leak in ("googleapis", "api.groq", "cerebras", "openrouter", "nvidia", "last_error", "attempts"):
        assert leak not in body, f"error response leaked {leak!r}: {r.text}"


def test_chat_error_carries_a_correlation_ref(app_client, install_token):
    r = app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    assert "ref: " in r.json()["detail"]
    assert "no provider could serve this request" in r.json()["detail"]


# ── the detail is not lost, it is just moved ────────────────────────────────


def test_the_real_cause_is_audited(app_client, install_token):
    app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    rows = [r for r in query(limit=20) if r["event_type"] == "upstream_error"]
    assert rows, "the upstream error must be recorded server-side"
    detail = json.loads(rows[0]["result_json"])["detail"]
    assert "all providers unavailable" in detail  # the operator still gets everything


def test_the_audited_ref_matches_the_one_the_client_was_given(app_client, install_token):
    r = app_client.post("/v1/chat", headers=_auth(install_token), json=CHAT)

    client_ref = r.json()["detail"].split("ref: ")[1].rstrip(")")
    rows = [row for row in query(limit=20) if row["event_type"] == "upstream_error"]
    audited_refs = [json.loads(row["params_json"])["ref"] for row in rows]

    assert client_ref in audited_refs, "the ref must be usable to look the error up"


# ── the same treatment on the other data-plane paths ────────────────────────


def test_embed_error_is_sanitised(app_client, install_token):
    r = app_client.post("/v1/embed", headers=_auth(install_token), json={"text": "hello"})

    # 503 (no embedders configured) or a sanitised upstream failure — either
    # way, no raw provider words.
    assert r.status_code in (502, 503)
    assert "googleapis" not in r.text.lower()


def test_batch_entry_error_is_sanitised(app_client, install_token):
    """/v1/chat/batch returns a per-entry error dict; it must be sanitised too,
    and must not be an internal exception string."""
    r = app_client.post(
        "/v1/chat/batch", headers=_auth(install_token), json={"calls": [CHAT]}
    )

    assert r.status_code == 200
    entry = r.json()["results"][0]
    assert "last_error" not in json.dumps(entry).lower()
    assert "attribute" not in json.dumps(entry).lower()  # no raw AttributeError


# ── the A1 regression this finding surfaced ─────────────────────────────────


def test_batch_forwards_the_auth_header(app_client, install_token):
    """A1 added require_install_token to chat(), but chat_batch called
    chat(call, request) without forwarding authorization, so every entry came
    back as "'Header' object has no attribute 'startswith'". Pin the fix: a
    batch with a valid token must reach the provider layer (503 = tried and
    found none) rather than dying on the auth check."""
    r = app_client.post("/v1/chat/batch", headers=_auth(install_token), json={"calls": [CHAT]})

    entry = r.json()["results"][0]
    assert entry["status_code"] == 503, entry  # reached the providers, not an AttributeError


def test_batch_without_a_token_is_still_rejected(app_client):
    r = app_client.post("/v1/chat/batch", json={"calls": [CHAT]})
    assert r.status_code == 401

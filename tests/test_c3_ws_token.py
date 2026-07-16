"""Session 12, finding C3 — the WS install token was accepted in the query string.

`WS /v1/channels/{name}?token=...` put the credential in the one part of a
request that gets written down everywhere: proxy and server access logs,
browser history, Referer headers, metrics labels. The token ends up at rest in
places nobody is protecting, long after the connection closed.

The token is now accepted from the Authorization header only.
"""

from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from glc.audit import query


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── the header is the only way in ───────────────────────────────────────────


def test_header_token_connects(app_client, install_token):
    with app_client.websocket_connect("/v1/channels/telegram", headers=_auth(install_token)) as ws:
        assert ws is not None


def test_query_string_token_is_refused_even_when_correct(app_client, install_token):
    """The token is valid; the channel it arrived on is not. Accepting it here
    is what put the credential in the access log in the first place."""
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
            ws.receive_text()


def test_query_string_attempt_is_audited(app_client, install_token):
    """Fail loudly rather than with a bare 1008, so an operator whose adapter
    stopped connecting can see why."""
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
            ws.receive_text()

    events = [r["event_type"] for r in query(limit=20)]
    assert "ws_token_in_query_string" in events


def test_no_token_at_all_is_still_refused(app_client):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect("/v1/channels/telegram") as ws:
            ws.receive_text()


def test_a_wrong_header_token_is_refused(app_client):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(
            "/v1/channels/telegram", headers=_auth("not-the-token")
        ) as ws:
            ws.receive_text()


def test_a_non_bearer_header_is_refused(app_client, install_token):
    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(
            "/v1/channels/telegram", headers={"Authorization": install_token}
        ) as ws:
            ws.receive_text()


# ── the shipped clients do not put the token in a URL ────────────────────────


def test_no_shipped_client_interpolates_a_token_into_a_url():
    """The dev bridges used to build ws://...?token={the real token}. Pin that
    none of them do, so the credential cannot drift back into a URL by habit.

    Looks for the interpolation `?token={`, not the bare string, so that prose
    about the finding does not trip the check.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = [
        str(p.relative_to(root))
        for p in root.joinpath("glc").rglob("*.py")
        if "?token={" in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert offenders == []

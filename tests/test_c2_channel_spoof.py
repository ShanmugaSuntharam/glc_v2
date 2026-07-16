"""Session 12, finding C2 / leak 9 (cross-channel envelope spoofing): the
WS /v1/channels/{name} route must reject an envelope whose declared
env.channel differs from the route it arrived on, so a compromised adapter
cannot impersonate another channel to borrow its allowlist / owner pairing.
Restores invariant 2 (every action checked against the actual channel).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from starlette.websockets import WebSocketDisconnect


def _auth(token: str) -> dict:
    """C3: the token goes in the header, never the query string."""
    return {"Authorization": f"Bearer {token}"}


def _envelope(channel: str) -> dict:
    return {
        "channel": channel,
        "channel_user_id": "attacker-id",
        "user_handle": "attacker",
        "text": "hi",
        "trust_level": "untrusted",
        "arrived_at": datetime.now(UTC).isoformat(),
    }


def test_ws_rejects_cross_channel_spoof(app_client, install_token):
    """An adapter bound to /telegram declaring env.channel='discord' is
    rejected and the socket is closed."""
    with app_client.websocket_connect("/v1/channels/telegram", headers=_auth(install_token)) as ws:
        ws.send_text(json.dumps(_envelope("discord")))
        resp = json.loads(ws.receive_text())
        assert "channel mismatch" in resp["error"]
        # The server closes the connection after the mismatch.
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()


def test_ws_accepts_matching_channel(app_client, install_token):
    """A matching envelope is NOT treated as a spoof and the socket stays
    open (the message goes on to the normal allowlist path)."""
    with app_client.websocket_connect("/v1/channels/telegram", headers=_auth(install_token)) as ws:
        ws.send_text(json.dumps(_envelope("telegram")))
        resp = json.loads(ws.receive_text())
        assert "channel mismatch" not in json.dumps(resp)

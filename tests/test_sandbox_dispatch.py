"""Session 12, finding A3: channel-adapter code moves into its own Modal
Sandbox with a per-channel network egress policy (glc/channels.yaml) when
GLC_ADAPTER_SANDBOX=1. These tests cover the gating/policy logic and the
in-sandbox runner's dispatch function directly - no live Modal Sandbox
involved (that's verified manually against the real deployment; creating
real Sandboxes in every CI run would be slow and require Modal auth).
"""

from __future__ import annotations

import base64

from glc.sandbox import adapter_runner, dispatch


def test_sandbox_disabled_by_default(monkeypatch):
    monkeypatch.delenv("GLC_ADAPTER_SANDBOX", raising=False)
    assert dispatch.sandbox_enabled() is False


def test_sandbox_enabled_via_env_var(monkeypatch):
    monkeypatch.setenv("GLC_ADAPTER_SANDBOX", "1")
    assert dispatch.sandbox_enabled() is True


def test_network_policy_telegram_has_allowlist():
    policy = dispatch.network_policy_for("telegram")
    assert policy == {"block_network": False, "outbound_domains": ["api.telegram.org"]}


def test_network_policy_whatsapp_has_two_domains():
    policy = dispatch.network_policy_for("whatsapp")
    assert policy["outbound_domains"] == ["graph.facebook.com", "api.twilio.com"]


def test_network_policy_webui_blocks_network():
    assert dispatch.network_policy_for("webui")["block_network"] is True


def test_network_policy_signal_blocks_network():
    assert dispatch.network_policy_for("signal")["block_network"] is True


def test_network_policy_unknown_channel_defaults_to_no_egress():
    policy = dispatch.network_policy_for("not_a_real_channel")
    assert policy == {"block_network": False, "outbound_domains": []}


def test_adapter_secrets_only_cover_channels_with_real_credentials():
    # webui/local_mic/signal/twilio_voice/discord/slack/matrix/line/imap
    # have no real credential to scope a secret to.
    assert "webui" not in dispatch.ADAPTER_SECRETS
    assert "signal" not in dispatch.ADAPTER_SECRETS
    assert "telegram" in dispatch.ADAPTER_SECRETS
    assert "whatsapp" in dispatch.ADAPTER_SECRETS


def test_adapter_runner_on_message_round_trips_through_json():
    """whatsapp's on_message expects the {"raw_body","headers"} wrapper
    shape the webhook route builds. An unsigned/unrecognized payload is a
    deterministic, network-free None - a real code path, not a stub."""
    payload = {
        "raw_body_b64": base64.b64encode(b'{"not": "a real whatsapp payload"}').decode(),
        "headers": {},
    }
    assert adapter_runner.dispatch("on_message", "whatsapp", payload) == {"result": None}


def test_adapter_runner_send_round_trips_through_json(app_client):
    """No pairing record exists in the fresh isolated test DB, so send()
    deterministically returns an outbound_blocked error with no network
    call - app_client boots the app so config/pairing singletons exist."""
    payload = {"reply": {"channel": "whatsapp", "channel_user_id": "unpaired-user", "text": "hi"}}
    out = adapter_runner.dispatch("send", "whatsapp", payload)
    assert out["result"]["code"] == "outbound_blocked"


def test_adapter_runner_unknown_channel_reports_error_not_crash():
    payload = {"raw_body_b64": base64.b64encode(b"{}").decode(), "headers": {}}
    out = adapter_runner.dispatch("on_message", "definitely_unknown_channel", payload)
    assert "error" in out
    assert "KeyError" in out["error"]


def test_channel_webhook_unchanged_when_sandbox_disabled(app_client, monkeypatch):
    """Default (test/local) behaviour must be byte-for-byte the same
    in-process path as before this finding - webui has no credential
    requirements so its webhook can run end to end."""
    monkeypatch.delenv("GLC_ADAPTER_SANDBOX", raising=False)
    r = app_client.post("/v1/channels/webui/webhook", json={"text": "hello"})
    assert r.status_code == 200

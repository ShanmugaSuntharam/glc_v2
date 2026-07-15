"""Session 12, finding A1: the data plane (chat/embed/vision/speak/
transcribe) accepted requests with no credential at all, letting anyone
with the URL trigger paid provider calls. Fix: require the install
token, same as the control plane already did.
"""

from __future__ import annotations


def test_chat_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/chat", json={"prompt": "hi"})
    assert r.status_code == 401


def test_chat_batch_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/chat/batch", json={"calls": []})
    assert r.status_code == 401


def test_vision_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/vision", json={"prompt": "describe", "image": "https://example.com/x.png"})
    assert r.status_code == 401


def test_embed_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/embed", json={"text": "hi"})
    assert r.status_code == 401


def test_speak_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/speak", json={"text": "hi"})
    assert r.status_code == 401


def test_transcribe_without_token_is_unauthorized(app_client):
    r = app_client.post("/v1/transcribe", json={"audio_b64": "AA==", "mime": "audio/wav"})
    assert r.status_code == 401


def test_chat_with_bad_token_is_forbidden(app_client):
    r = app_client.post("/v1/chat", headers={"Authorization": "Bearer bogus"}, json={"prompt": "hi"})
    assert r.status_code == 403


def test_chat_with_valid_token_passes_auth(app_client, install_token):
    """Auth succeeds; the request proceeds into the pipeline (no providers
    wired in tests, so it fails downstream — but not with 401/403)."""
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.post("/v1/chat", headers=h, json={"prompt": "hi"})
    assert r.status_code not in (401, 403)

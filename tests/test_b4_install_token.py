"""Session 12, finding B4 / leak 4 (install token readable in-process): the
control token sat on disk in plaintext at ~/.glc/install_token with mode
0600. Mode 0600 keeps other Unix users out; it does nothing about other code
running as the same user, which is every adapter in the gateway process:

    tok = open(os.path.expanduser("~/.glc/install_token")).read().strip()

The gateway now stores only sha256(token) — reading the file yields a hash,
which is useless as a bearer credential.
"""

from __future__ import annotations

import hashlib
import os

import glc.config as config


def _read_token_file() -> str:
    """Leak 4's exploit verbatim: open the file and read it."""
    return config.install_token_path().read_text().strip()


# ── the leak is closed ──────────────────────────────────────────────────────


def test_disk_holds_a_hash_not_the_token(monkeypatch):
    monkeypatch.setenv(config.INSTALL_TOKEN_ENV, "super-secret-token")

    config.seal_install_token()

    on_disk = _read_token_file()
    assert on_disk != "super-secret-token"
    assert on_disk == hashlib.sha256(b"super-secret-token").hexdigest()
    # what leak 4 reads is not a usable credential
    assert config.verify_install_token(on_disk) is False


def test_env_var_is_scrubbed_after_seal(monkeypatch):
    """Same move as A4: no os.getenv() path to the credential either."""
    monkeypatch.setenv(config.INSTALL_TOKEN_ENV, "super-secret-token")

    config.seal_install_token()

    assert os.getenv(config.INSTALL_TOKEN_ENV) is None


def test_operator_supplied_token_verifies(monkeypatch):
    monkeypatch.setenv(config.INSTALL_TOKEN_ENV, "super-secret-token")
    config.seal_install_token()

    assert config.verify_install_token("super-secret-token") is True
    assert config.verify_install_token("wrong-token") is False
    assert config.verify_install_token(None) is False
    assert config.verify_install_token("") is False


# ── the legacy installation keeps working ───────────────────────────────────


def test_legacy_plaintext_file_is_migrated_in_place_and_token_still_works(monkeypatch):
    """A live installation already has a plaintext token on the Volume. It
    must be hashed in place -- the operator's existing token keeps working,
    but the recoverable copy goes away."""
    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    config.install_token_path().write_text("legacy-plaintext-token")

    config.seal_install_token()

    assert _read_token_file() == hashlib.sha256(b"legacy-plaintext-token").hexdigest()
    assert config.verify_install_token("legacy-plaintext-token") is True  # still valid


def test_seal_is_idempotent_over_an_already_hashed_file(monkeypatch):
    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    config.install_token_path().write_text("legacy-plaintext-token")

    config.seal_install_token()
    first = _read_token_file()
    config._token_hash = None
    config.seal_install_token()  # second boot: file already hashed

    assert _read_token_file() == first
    assert config.verify_install_token("legacy-plaintext-token") is True


# ── fresh install / rotation ────────────────────────────────────────────────


def test_fresh_install_returns_the_token_once_then_only_the_hash(monkeypatch):
    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    p = config.install_token_path()
    if p.exists():
        p.unlink()

    fresh = config.seal_install_token()

    assert fresh  # shown exactly once
    assert config.verify_install_token(fresh) is True
    assert _read_token_file() != fresh  # never persisted in the clear


def test_seal_returns_none_when_token_already_exists(monkeypatch):
    """Nothing to show: an existing token is never recoverable."""
    monkeypatch.setenv(config.INSTALL_TOKEN_ENV, "super-secret-token")
    assert config.seal_install_token() is None


def test_rotate_mints_a_new_token_and_invalidates_the_old(monkeypatch):
    monkeypatch.setenv(config.INSTALL_TOKEN_ENV, "super-secret-token")
    config.seal_install_token()

    new = config.rotate_install_token()

    assert config.verify_install_token(new) is True
    assert config.verify_install_token("super-secret-token") is False


# ── the routes still authenticate correctly end to end ──────────────────────


def test_data_plane_accepts_the_real_token(app_client, install_token):
    r = app_client.get("/v1/providers", headers={"Authorization": f"Bearer {install_token}"})
    assert r.status_code == 200


def test_data_plane_rejects_the_hash_from_disk(app_client, install_token):
    """The end-to-end version of leak 4: steal the file contents, present them
    as a bearer token, get nowhere."""
    stolen = _read_token_file()
    r = app_client.get("/v1/providers", headers={"Authorization": f"Bearer {stolen}"})
    assert r.status_code == 403


def test_ws_rejects_the_hash_from_disk(app_client, install_token):
    stolen = _read_token_file()
    with app_client.websocket_connect(f"/v1/channels/telegram?token={install_token}") as ws:
        assert ws is not None  # the real token still connects

    import pytest
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with app_client.websocket_connect(f"/v1/channels/telegram?token={stolen}") as ws:
            ws.receive_text()

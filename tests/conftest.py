"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import secrets

import pytest


@pytest.fixture(autouse=True)
def _isolated_glc_state(monkeypatch, tmp_path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setenv("GLC_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("GLC_AUDIT_DB", str(tmp_path / "audit.sqlite"))
    monkeypatch.setenv("GLC_PAIRING_DB", str(tmp_path / "pairings.sqlite"))
    monkeypatch.setenv("GLC_GATEWAY_DB", str(tmp_path / "gateway.sqlite"))

    # Reset singletons that cache config-dir at first access.
    import glc.config as _cfg

    _cfg.CONFIG_DIR = cfg
    # B4: the install token is sealed to a module-level hash; roll it per-test.
    _cfg._token_hash = None
    _cfg._sealed = False
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    import glc.policy.engine as _e

    _e._engine = None
    import glc.audit.store as _a

    _a._singleton = None
    _a._commit_hook = None  # A6: don't let a test's volume-commit hook leak

    # A4: the provider-key vault snapshots + scrubs os.environ on seal(); reset
    # it per-test so a key sealed by one test never leaks into the next.
    import glc.security.keyvault as _kv

    _kv._store.clear()
    _kv._sealed = False
    yield


@pytest.fixture
def install_token(monkeypatch):
    """The per-installation token, supplied to the gateway rather than read
    back from it.

    Finding B4: the gateway now stores only sha256(token), so there is no
    plaintext anywhere for a test (or an attacker) to read. Tests therefore
    hand the gateway a known token via GLC_INSTALL_TOKEN before boot; the
    lifespan seals it (scrubbing the env var) and verifies against the hash.
    app_client depends on this fixture so the env is always set before the
    app's lifespan runs.
    """
    tok = "test-install-token-" + secrets.token_urlsafe(16)
    monkeypatch.setenv("GLC_INSTALL_TOKEN", tok)
    return tok


@pytest.fixture
def app_client(install_token):
    """TestClient pointed at a freshly-booted glc.main:app."""
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app) as c:
        yield c

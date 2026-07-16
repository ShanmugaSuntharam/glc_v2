"""Shared fixtures.

Each test session gets a fresh isolated config/db dir so user state at
~/.glc/ is never touched. Per-test, the audit / pairing / gateway DBs
are rolled fresh.
"""

from __future__ import annotations

import pytest

# The suite's install token. B3/B4: the gateway keeps only sha256(token), so a
# test cannot read one back — it supplies a known one instead, and thereby acts
# as the installer when it calls force_pair_owner().
TEST_INSTALL_TOKEN = "test-install-token-for-the-suite"


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
    # B4/B3: the install token seals to a module-level hash and derives the
    # pairing signing key; roll all of it per-test.
    _cfg._token_hash = None
    _cfg._sealed = False
    _cfg._pairing_key = None
    import glc.security.pairing as _p

    _p._singleton = None
    import glc.security.rate_limits as _r

    _r._limiter = None
    # C5: the data-plane rate windows are process-global; roll them per-test so
    # one test's requests never exhaust another's budget.
    import glc.security.quota as _q

    _q.reset()
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


@pytest.fixture(autouse=True)
def _installer_token(_isolated_glc_state, monkeypatch):
    """Seal a known install token for every test.

    Two things depend on this:
      * B4 — the routes verify against sha256(token), so the suite has to
        supply the token rather than read one back.
      * B3 — sealing is what derives the pairing signing key, so signing is
        active in tests (as it is on a real deployment supplying
        GLC_INSTALL_TOKEN) rather than silently falling back to unsigned mode.

    seal_install_token() scrubs GLC_INSTALL_TOKEN from the environment, which
    is exactly the point in production. Tests, though, legitimately act as the
    *installer* when they call force_pair_owner(), so the variable is restored
    afterwards — the same thing an installer script does in its own process.
    """
    import glc.config as _cfg

    monkeypatch.setenv(_cfg.INSTALL_TOKEN_ENV, TEST_INSTALL_TOKEN)
    _cfg.seal_install_token()
    monkeypatch.setenv(_cfg.INSTALL_TOKEN_ENV, TEST_INSTALL_TOKEN)
    yield


@pytest.fixture
def install_token():
    """The token the suite sealed — supplied to the gateway, never read back."""
    return TEST_INSTALL_TOKEN


@pytest.fixture
def app_client(install_token, monkeypatch):
    """TestClient pointed at a freshly-booted glc.main:app."""
    from fastapi.testclient import TestClient

    import glc.config as _cfg
    import glc.main as m

    with TestClient(m.app) as c:
        # The lifespan's seal scrubbed GLC_INSTALL_TOKEN again (B4). Restore it
        # so a test that acts as the installer after boot still can.
        monkeypatch.setenv(_cfg.INSTALL_TOKEN_ENV, install_token)
        yield c

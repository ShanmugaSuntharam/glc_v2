"""Session 12, finding A4 (leak 1): provider API keys must not remain in
os.environ where any in-process code can read them with a single
os.getenv() call.

glc.security.keyvault.seal() snapshots every provider key into a private
store and scrubs the environment; glc.providers / glc.embedders read
through keyvault.get() instead. These tests exercise that behaviour
directly — no live Modal deployment involved.
"""

from __future__ import annotations

import os

import pytest

from glc.security import keyvault


def test_before_seal_get_reads_live_env(monkeypatch):
    """Local dev / test / daemon behaviour is unchanged until seal()."""
    monkeypatch.setenv("GEMINI_API_KEY", "mock-secret-value")
    assert keyvault.get("GEMINI_API_KEY") == "mock-secret-value"
    assert os.getenv("GEMINI_API_KEY") == "mock-secret-value"


def test_seal_scrubs_key_from_environ_but_get_still_serves_it(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "mock-secret-value")

    keyvault.seal()

    # The Section-2 theft line now returns nothing...
    assert os.getenv("GEMINI_API_KEY") is None
    assert "GEMINI_API_KEY" not in os.environ
    # ...but the one legitimate chokepoint still serves it.
    assert keyvault.get("GEMINI_API_KEY") == "mock-secret-value"
    assert keyvault.is_sealed() is True


def test_seal_scrubs_every_registered_provider_key(monkeypatch):
    for name in keyvault.PROVIDER_KEY_ENV_VARS:
        monkeypatch.setenv(name, f"mock-{name}")

    keyvault.seal()

    for name in keyvault.PROVIDER_KEY_ENV_VARS:
        assert name not in os.environ, f"{name} was not scrubbed from os.environ"
        assert keyvault.get(name) == f"mock-{name}"


def test_seal_is_idempotent_and_missing_keys_are_fine(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    keyvault.seal()
    keyvault.seal()  # second call must not raise
    assert keyvault.get("GROQ_API_KEY") is None


def test_get_rejects_non_provider_env_var():
    """The vault can never be repurposed to fetch non-secret configuration."""
    with pytest.raises(KeyError):
        keyvault.get("GLC_PORT")


def test_non_secret_config_is_never_scrubbed(monkeypatch):
    """Model names / URLs are configuration, not secrets — they must survive."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")

    keyvault.seal()

    assert os.getenv("GEMINI_MODEL") == "gemini-2.5-flash"
    assert os.getenv("OLLAMA_URL") == "http://localhost:11434"


def test_build_providers_uses_the_vault_after_seal(monkeypatch):
    """The gateway still builds its providers from the sealed vault even
    though the key is no longer visible in os.environ."""
    from glc.cache import GeminiCache

    monkeypatch.setenv("GEMINI_API_KEY", "mock-gemini")
    keyvault.seal()
    assert os.getenv("GEMINI_API_KEY") is None  # gone from the environment

    import glc.providers as P

    providers = P.build_providers(GeminiCache(ttl_seconds=300))
    assert "gemini" in providers  # built via keyvault.get(), not os.getenv()

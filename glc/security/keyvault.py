"""Session 12, finding A4 (leak 1): provider API keys must not sit in
os.environ, where any in-process code can read every one of them with a
single os.getenv() call.

glc_v1 / Move 1 loaded all provider keys into the gateway process
environment at startup and left them there for the whole container
lifetime. That is the shared-process env-var theft from Section 2 of the
class notes:

    os.environ["GEMINI_API_KEY"]   # any adapter / poisoned dependency /
                                   # injected code reads every provider key

This module is the single narrow chokepoint for provider credentials. At
gateway startup glc.main's lifespan calls seal(): each provider key is
snapshotted into a private in-process store and then DELETED from
os.environ, so afterwards os.getenv("GEMINI_API_KEY") returns None and
/proc/self/environ no longer carries the secret. The only legitimate
readers (glc.providers, glc.embedders) go through get() instead.

This is the option-B hardening of A4. It removes the two things the
finding names: the "all keys resident in the environment, forever, for
everything" blast radius, and the single shared-Secret shape (it is
deployed alongside per-provider Modal Secrets in modal_app.py, so each key
is scoped and rotatable on its own). It does NOT, by itself, stop trusted
in-gateway code from calling get() — the full per-call Modal Sandbox
isolation (Moves 2-4, option A) is the capstone-scope completion tracked
in docs/SECURITY_FIXES.md. Restores security invariant 1 ("adapters must
never see provider API keys") for the shared-environment vector.
"""

from __future__ import annotations

import os
import threading

# The provider secrets, keyed by the env-var name Move 1 delivered them
# under. ONLY real credentials belong here — model names, base URLs, and
# per-channel verify tokens are configuration, not secrets, and stay in the
# environment untouched.
PROVIDER_KEY_ENV_VARS: tuple[str, ...] = (
    "GEMINI_API_KEY",
    "NVIDIA_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "GITHUB_ACCESS_TOKEN",
)

_lock = threading.Lock()
_store: dict[str, str] = {}
_sealed = False


def seal() -> None:
    """Snapshot every provider key out of os.environ into the private store
    and delete it from the environment.

    Idempotent and thread-safe; called once at gateway startup (before any
    provider is built). After this returns, os.getenv(<provider key>) is
    None and the key exists only inside this module.
    """
    global _sealed
    with _lock:
        for name in PROVIDER_KEY_ENV_VARS:
            val = os.environ.pop(name, None)
            if val is not None:
                _store[name] = val
        _sealed = True


def is_sealed() -> bool:
    return _sealed


def get(env_var: str) -> str | None:
    """Return a provider key by its env-var name.

    Before seal() this reads the live environment, so local dev, the
    `daemon/` runner, and the test suite behave exactly as they did before
    this finding. After seal() it serves the private snapshot — and the key
    is no longer anywhere in os.environ.

    Raises KeyError if asked for anything that is not a registered provider
    secret, so this accessor can never be quietly repurposed to fetch
    non-secret configuration.
    """
    if env_var not in PROVIDER_KEY_ENV_VARS:
        raise KeyError(f"{env_var} is not a registered provider key")
    if _sealed:
        return _store.get(env_var)
    return os.getenv(env_var)

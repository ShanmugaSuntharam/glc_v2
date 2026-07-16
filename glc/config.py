"""Loads channels.yaml and policy.yaml. Resolves user-config directory.

The default config lives in `~/.glc/`. Override with GLC_CONFIG_DIR for
tests and CI. The directory is created on import if missing.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

import yaml

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CONFIG_DIR = Path(os.getenv("GLC_CONFIG_DIR", str(DEFAULT_DIR)))
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Packaged defaults shipped with glc (under the policy/ subpackage).
PACKAGED_POLICY = Path(__file__).parent / "policy" / "policy.yaml"
PACKAGED_CHANNELS = Path(__file__).parent / "channels.yaml"


def policy_yaml_path() -> Path:
    user = CONFIG_DIR / "policy.yaml"
    return user if user.exists() else PACKAGED_POLICY


def channels_yaml_path() -> Path:
    user = CONFIG_DIR / "channels.yaml"
    return user if user.exists() else PACKAGED_CHANNELS


def load_channels() -> dict:
    p = channels_yaml_path()
    if not p.exists():
        return {"channels": {}}
    return yaml.safe_load(p.read_text()) or {"channels": {}}


# ────────────────────────────────────────────────────────────────────────────
# Finding B4 (leak 4) — the install token was readable in-process
# ────────────────────────────────────────────────────────────────────────────
# The per-installation control token used to sit on disk in PLAINTEXT at
# ~/.glc/install_token with mode 0600. Mode 0600 keeps other *Unix users* out;
# it does nothing about other *code running as the same user*, which is every
# adapter sharing the gateway process. So the whole credential was one line
# away:
#
#     tok = open(os.path.expanduser("~/.glc/install_token")).read().strip()
#     httpx.post(".../v1/control/kill", headers={"Authorization": f"Bearer {tok}"})
#
# The fix is the one used for passwords everywhere: STOP STORING A RECOVERABLE
# SECRET. The gateway never needs to *recover* the token, only to *verify* a
# presented one, so only sha256(token) is kept — on disk and in memory. Reading
# the file now yields a hash, which is useless as a bearer credential.
#
# Where the plaintext comes from, in priority order:
#   1. GLC_INSTALL_TOKEN (env / Modal Secret) — the operator picks it, so they
#      already know it and nothing ever has to hand it back. This is the right
#      source for a Modal deployment. It is scrubbed from os.environ on seal,
#      so in-process code cannot os.getenv() it either (same move as A4).
#   2. A legacy plaintext install_token file — hashed IN PLACE on first boot,
#      so an existing installation's token keeps working while the plaintext
#      leaves the disk.
#   3. Freshly generated, if there is nothing at all — returned once by
#      seal_install_token() so the caller can show the operator, then only the
#      hash is retained.
#
# Honest scope: verification-only storage means no on-disk or in-environment
# copy to steal. It does not stop in-process code from reading a token off a
# request in flight, or from calling verify_install_token() as an oracle
# (guessing is infeasible against a 256-bit token). Binding the token to the
# gateway alone is, as the notes say, ultimately process separation.

INSTALL_TOKEN_ENV = "GLC_INSTALL_TOKEN"

_token_hash: str | None = None
_sealed = False

# Finding B3: the key that signs pairing records (glc/security/pairing.py).
# It is derived from the install token's PLAINTEXT and kept only in memory --
# deliberately NOT from anything on disk. Deriving it from the stored sha256
# would be pointless: that hash sits in install_token, so in-process code
# could re-derive the key and forge pairings at will.
#
# Consequence: the key exists only when seal_install_token() sees a plaintext
# (i.e. GLC_INSTALL_TOKEN is supplied, or the token was just generated /
# migrated). A deployment that supplies GLC_INSTALL_TOKEN gets it on every
# boot, so signatures stay stable across restarts. With no plaintext there is
# no key, and pairing.py falls back to unsigned mode (see its header).
_pairing_key: str | None = None


def _derive_pairing_key(tok: str) -> str:
    return hashlib.sha256(f"{tok.strip()}:glc-pairing-signing-v1".encode()).hexdigest()


def pairing_signing_key() -> str | None:
    """The in-memory pairing signing key, or None if this process never saw
    the token plaintext."""
    return _pairing_key


def install_token_path() -> Path:
    return CONFIG_DIR / "install_token"


def _hash_token(tok: str) -> str:
    return hashlib.sha256(tok.strip().encode()).hexdigest()


def _looks_hashed(value: str) -> bool:
    """A stored sha256 is 64 hex chars; a real token is url-safe base64 of 32
    bytes (~43 chars, and usually not all-hex), so this cleanly separates a
    migrated file from a legacy plaintext one."""
    v = value.strip()
    if len(v) != 64:
        return False
    try:
        int(v, 16)
    except ValueError:
        return False
    return True


def _write_hash(digest: str) -> None:
    p = install_token_path()
    p.write_text(digest)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def seal_install_token() -> str | None:
    """Resolve the install token once at gateway startup, keep only its hash,
    and remove every recoverable copy (env var scrubbed, disk plaintext
    replaced by its hash).

    Returns the plaintext ONLY when a brand-new token had to be generated —
    the single moment it can ever be shown to the operator. Returns None when
    the token came from GLC_INSTALL_TOKEN (the operator already knows it) or
    from an existing installation.
    """
    global _token_hash, _sealed, _pairing_key

    # 1. operator-supplied (env / Modal Secret) — scrub it like a provider key.
    env_tok = os.environ.pop(INSTALL_TOKEN_ENV, None)
    if env_tok and env_tok.strip():
        _token_hash = _hash_token(env_tok)
        _pairing_key = _derive_pairing_key(env_tok)  # B3
        _write_hash(_token_hash)
        _sealed = True
        return None

    p = install_token_path()
    if p.exists():
        stored = p.read_text().strip()
        if _looks_hashed(stored):
            # 2a. already migrated. No plaintext here, so no pairing key can be
            # derived -- any key from an earlier seal in this process is kept.
            _token_hash = stored
        else:
            # 2b. legacy plaintext -> hash in place. The existing token stays
            # valid; only its recoverable copy goes away.
            _token_hash = _hash_token(stored)
            _pairing_key = _derive_pairing_key(stored)  # B3
            _write_hash(_token_hash)
        _sealed = True
        return None

    # 3. fresh install: generate, show once, keep only the hash.
    tok = secrets.token_urlsafe(32)
    _token_hash = _hash_token(tok)
    _pairing_key = _derive_pairing_key(tok)  # B3
    _write_hash(_token_hash)
    _sealed = True
    return tok


def install_token_is_set() -> bool:
    return _token_hash is not None or install_token_path().exists()


def install_token_hash() -> str | None:
    """The stored verifier. Safe to expose: a hash cannot be presented as a
    bearer token."""
    if _token_hash is not None:
        return _token_hash
    p = install_token_path()
    if p.exists():
        stored = p.read_text().strip()
        return stored if _looks_hashed(stored) else _hash_token(stored)
    return None


def verify_install_token(presented: str | None) -> bool:
    """Constant-time verification against the stored hash.

    hmac.compare_digest, not ==, so the check cannot be turned into a timing
    oracle that leaks the token a character at a time.
    """
    if not presented:
        return False
    expected = install_token_hash()
    if not expected:
        return False
    return hmac.compare_digest(_hash_token(presented), expected)


def rotate_install_token() -> str:
    """Mint a fresh token, store only its hash, and return the plaintext once.
    The only way back in if the operator loses the token."""
    global _token_hash, _sealed, _pairing_key
    tok = secrets.token_urlsafe(32)
    _token_hash = _hash_token(tok)
    _pairing_key = _derive_pairing_key(tok)  # B3
    _write_hash(_token_hash)
    _sealed = True
    return tok

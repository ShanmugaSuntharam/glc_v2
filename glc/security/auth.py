"""Shared install-token check.

Originally lived only in routes/control.py, protecting the control
plane. Session 12 finding A1: the data-plane routes (chat/embed/vision/
speak/transcribe) had no equivalent check, so anyone with the gateway
URL could trigger paid provider calls with no credential at all.
"""

from __future__ import annotations

from fastapi import HTTPException

from glc.config import verify_install_token


def require_install_token(authorization: str | None) -> None:
    # Session 12 finding B4: verify against the stored hash rather than
    # fetching a plaintext token to compare. verify_install_token uses
    # hmac.compare_digest, so this is also no longer a timing oracle.
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if not verify_install_token(presented):
        raise HTTPException(403, "install token mismatch")

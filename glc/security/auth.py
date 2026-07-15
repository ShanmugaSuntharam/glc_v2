"""Shared install-token check.

Originally lived only in routes/control.py, protecting the control
plane. Session 12 finding A1: the data-plane routes (chat/embed/vision/
speak/transcribe) had no equivalent check, so anyone with the gateway
URL could trigger paid provider calls with no credential at all.
"""

from __future__ import annotations

from fastapi import HTTPException

from glc.config import get_or_create_install_token


def require_install_token(authorization: str | None) -> None:
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(403, "install token mismatch")

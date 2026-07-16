"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

All endpoints require the installation token (Authorization: Bearer ...).
The kill endpoint binds 127.0.0.1 only; the host check is enforced here.
"""

from __future__ import annotations

import os
import signal
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.audit import append as audit_append
from glc.security import quota
from glc.security.auth import require_install_token as _require_token
from glc.security.pairing import CODE_TTL_SECONDS, get_pairing_store

router = APIRouter()


class PairRequest(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str = ""
    trust_level: str = "user_paired"


class PairResponse(BaseModel):
    code: str
    expires_at: float
    ttl_seconds: int


class PairConfirmRequest(BaseModel):
    code: str


@router.post("/v1/control/pair", response_model=PairResponse)
async def pair(req: PairRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    if req.trust_level not in ("user_paired", "owner_paired"):
        raise HTTPException(400, f"trust_level must be user_paired or owner_paired, got {req.trust_level!r}")
    code, expires_at = get_pairing_store().issue_code(
        req.channel,
        req.channel_user_id,
        req.user_handle,
        requested_trust_level=req.trust_level,
    )
    return PairResponse(code=code, expires_at=expires_at, ttl_seconds=CODE_TTL_SECONDS)


@router.post("/v1/control/pair/confirm")
async def pair_confirm(
    req: PairConfirmRequest, request: Request, authorization: str | None = Header(default=None)
):
    _require_token(authorization)
    # Finding C6: a six-digit code is 1,000,000 possibilities and lives for
    # five minutes. Unthrottled, that is a race an attacker wins; the guess cap
    # is the code's actual security, exactly as it is for any 2FA code.
    caller = request.client.host if request.client else "unknown"
    ok, why = quota.check_pair_confirm(caller)
    if not ok:
        audit_append(
            channel="_system",
            channel_user_id=caller,
            trust_level="untrusted",
            event_type="pair_confirm_rate_limited",
            result={"reason": why},
        )
        raise HTTPException(429, why)

    rec = get_pairing_store().confirm_code(req.code)
    if rec is None:
        # A wrong code is the shape of a brute force. One is a typo; a stream
        # of them is an attack, and the audit log is where that becomes visible.
        audit_append(
            channel="_system",
            channel_user_id=caller,
            trust_level="untrusted",
            event_type="pair_confirm_failed",
            result={"reason": "code unknown or expired"},
        )
        raise HTTPException(404, "code unknown or expired")
    return {
        "channel": rec.channel,
        "channel_user_id": rec.channel_user_id,
        "user_handle": rec.user_handle,
        "trust_level": rec.trust_level,
        "paired_at": rec.paired_at,
    }


@router.get("/v1/control/presence")
async def presence(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    state = request.app.state
    started = getattr(state, "started_at", time.time())
    pairings = get_pairing_store().all_pairings()
    return {
        "channels": getattr(state, "registered_channels", []),
        "paired_users": [
            {
                "channel": p.channel,
                "channel_user_id": p.channel_user_id,
                "user_handle": p.user_handle,
                "trust_level": p.trust_level,
            }
            for p in pairings
        ],
        "uptime_s": int(time.time() - started),
    }


@router.post("/v1/control/kill")
async def kill(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    client_host = request.client.host if request.client else "unknown"
    if os.getenv("GLC_KILL_ALLOW_REMOTE") != "1" and client_host not in ("127.0.0.1", "::1", "localhost"):
        # Finding B6: a refused kill is an attack signal — record it.
        audit_append(
            channel="_system",
            channel_user_id=client_host,
            trust_level="owner_paired",
            event_type="control_kill_denied",
            result={"reason": "not loopback", "client_host": client_host},
        )
        raise HTTPException(
            403,
            f"kill is restricted to loopback (got {client_host}). "
            "Set GLC_KILL_ALLOW_REMOTE=1 to override (not recommended).",
        )
    # Finding B6: terminating the gateway is the most consequential thing the
    # control plane can do, and it used to leave no trace at all. Record it
    # BEFORE dying — afterwards there is no process left to write anything.
    audit_append(
        channel="_system",
        channel_user_id=client_host,
        trust_level="owner_paired",
        event_type="control_kill_accepted",
        params={"client_host": client_host, "pid": os.getpid()},
    )
    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}

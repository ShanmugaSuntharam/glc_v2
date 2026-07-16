"""DM pairing flow.

A rotating six-digit code is issued per pairing request and expires after
five minutes. The owner enters the code through the WebUI to confirm.
Per-pairing trust levels live in ~/.glc/pairings.sqlite: owner_paired for
the installation owner, user_paired for explicitly-paired users.

The pairing store is sqlite-backed so it survives restarts.
"""

from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from glc import config

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))
CODE_TTL_SECONDS = 5 * 60

# ────────────────────────────────────────────────────────────────────────────
# Finding B3 (leak 3) — in-process privilege escalation to owner
# ────────────────────────────────────────────────────────────────────────────
# Two ways an adapter used to crown itself owner, both because everything
# shares one process:
#
#   1. call the installer's method directly -- it was guarded by a docstring:
#        get_pairing_store().force_pair_owner("telegram", "attacker-id")
#   2. skip the method entirely and write the row, since pairings.sqlite has
#      the same OS-layer writability as the audit db and lookup() trusted
#      whatever trust_level it found there:
#        sqlite3.connect(...).execute(
#            "INSERT OR REPLACE INTO pairings VALUES (...,'owner_paired',...)")
#
# Closing only (1) would be theatre while (2) stayed open, so both are closed:
#
#   * force_pair_owner() now requires the install token. It is an INSTALLER
#     capability, and after B4 the gateway keeps only sha256(token), so
#     in-process code cannot obtain it. Grants and denials are audited, so
#     escalation is never silent.
#   * Every pairing row is HMAC-signed over its contents, and lookup() /
#     owners() / all_pairings() REFUSE rows whose signature does not verify.
#     A row inserted straight into SQLite carries no valid signature, so it is
#     inert -- the escalation does not merely get noticed, it does not work.
#
# The key comes from config.pairing_signing_key(), derived from the install
# token's plaintext and held only in memory (never on disk -- see config.py).
# If this process never saw a plaintext there is no key, and the store runs in
# UNSIGNED mode: signatures are neither written nor enforced. That keeps local
# dev and a legacy install working, and it is why a real deployment should
# supply GLC_INSTALL_TOKEN.
#
# Honest scope: same ceiling as B2. The key lives in this process's memory, so
# code that goes looking can read it and forge a signature. What is closed is
# both named exploits; what remains needs the pairing store in its own process
# -- which is exactly the component separation the notes prescribe for leak 3.

SIGNATURE_VERSION = "v1"


class PairingPermissionError(PermissionError):
    """force_pair_owner() was called without the installer's token."""


def _resolve_path() -> str:
    return os.getenv("GLC_PAIRING_DB", str(DEFAULT_DIR / "pairings.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


def _sign(channel: str, channel_user_id: str, user_handle: str, trust_level: str, paired_at: float) -> str | None:
    """HMAC over everything that matters about a pairing — crucially including
    trust_level, so a row cannot be edited from user_paired up to owner_paired
    without invalidating it. None when this process has no key (unsigned mode)."""
    key = config.pairing_signing_key()
    if not key:
        return None
    payload = "\x1f".join(
        [SIGNATURE_VERSION, channel, channel_user_id, user_handle or "", trust_level, repr(float(paired_at))]
    )
    return hmac.new(key.encode(), payload.encode(), sha256).hexdigest()


def _signature_ok(row: sqlite3.Row) -> bool:
    """Verify one stored row. In unsigned mode (no key) everything passes —
    there is nothing to verify against."""
    expected = _sign(
        row["channel"],
        row["channel_user_id"],
        row["user_handle"] or "",
        row["trust_level"],
        float(row["paired_at"]),
    )
    if expected is None:
        return True
    stored = row["signature"] if "signature" in row.keys() else None
    if not stored:
        return False  # signing is on and this row was never signed -> forged
    return hmac.compare_digest(stored, expected)


@dataclass
class PairingRecord:
    channel: str
    channel_user_id: str
    user_handle: str
    trust_level: str
    paired_at: float


class PairingStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with _conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS pairings (
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    trust_level TEXT NOT NULL,
                    paired_at REAL NOT NULL,
                    signature TEXT,
                    PRIMARY KEY (channel, channel_user_id)
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS pending_codes (
                    code TEXT PRIMARY KEY,
                    channel TEXT NOT NULL,
                    channel_user_id TEXT NOT NULL,
                    user_handle TEXT,
                    requested_trust_level TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            # B3: add the signature column to a pre-existing table (CREATE
            # TABLE IF NOT EXISTS cannot).
            cols = {r["name"] for r in c.execute("PRAGMA table_info(pairings)").fetchall()}
            if "signature" not in cols:
                c.execute("ALTER TABLE pairings ADD COLUMN signature TEXT")
            c.execute("CREATE TABLE IF NOT EXISTS pairing_meta (key TEXT PRIMARY KEY, value TEXT)")
        self._migrate_unsigned_rows()

    def _migrate_unsigned_rows(self) -> None:
        """B3: sign the rows an existing installation already has, exactly once.

        Without this, upgrading would invalidate every real pairing and lock
        the owner out. It runs a single time (guarded by pairing_meta) so that
        a row an attacker inserts AFTER the migration is never legitimised by a
        later restart.
        """
        if not config.pairing_signing_key():
            return  # unsigned mode: nothing to migrate against
        with _conn() as c:
            done = c.execute("SELECT value FROM pairing_meta WHERE key='signed_migration'").fetchone()
            if done:
                return
            for r in c.execute("SELECT * FROM pairings").fetchall():
                if r["signature"]:
                    continue
                sig = _sign(
                    r["channel"], r["channel_user_id"], r["user_handle"] or "", r["trust_level"],
                    float(r["paired_at"]),
                )
                c.execute(
                    "UPDATE pairings SET signature=? WHERE channel=? AND channel_user_id=?",
                    (sig, r["channel"], r["channel_user_id"]),
                )
            c.execute("INSERT OR REPLACE INTO pairing_meta (key, value) VALUES ('signed_migration', ?)",
                      (str(time.time()),))

    def issue_code(
        self,
        channel: str,
        channel_user_id: str,
        user_handle: str = "",
        *,
        requested_trust_level: str = "user_paired",
    ) -> tuple[str, float]:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires_at = time.time() + CODE_TTL_SECONDS
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pending_codes
                   (code, channel, channel_user_id, user_handle,
                    requested_trust_level, expires_at) VALUES (?,?,?,?,?,?)""",
                (code, channel, channel_user_id, user_handle, requested_trust_level, expires_at),
            )
        return code, expires_at

    def confirm_code(self, code: str) -> PairingRecord | None:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM pending_codes WHERE code=?",
                (code,),
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] < time.time():
                c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
                return None
            paired_at = time.time()
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at, signature)
                   VALUES (?,?,?,?,?,?)""",
                (
                    row["channel"],
                    row["channel_user_id"],
                    row["user_handle"],
                    row["requested_trust_level"],
                    paired_at,
                    # B3: a legitimately-confirmed pairing is signed like any other.
                    _sign(
                        row["channel"],
                        row["channel_user_id"],
                        row["user_handle"] or "",
                        row["requested_trust_level"],
                        paired_at,
                    ),
                ),
            )
            c.execute("DELETE FROM pending_codes WHERE code=?", (code,))
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["requested_trust_level"],
                paired_at=paired_at,
            )

    def lookup(self, channel: str, channel_user_id: str) -> PairingRecord | None:
        with _conn() as c:
            row = c.execute(
                "SELECT * FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            ).fetchone()
            if row is None:
                return None
            # B3: a row written straight into SQLite carries no valid
            # signature. Refuse it -- an unverifiable pairing is no pairing.
            if not _signature_ok(row):
                return None
            return PairingRecord(
                channel=row["channel"],
                channel_user_id=row["channel_user_id"],
                user_handle=row["user_handle"] or "",
                trust_level=row["trust_level"],
                paired_at=float(row["paired_at"]),
            )

    def owners(self, channel: str | None = None) -> list[PairingRecord]:
        q = "SELECT * FROM pairings WHERE trust_level='owner_paired'"
        args: list = []
        if channel:
            q += " AND channel=?"
            args.append(channel)
        with _conn() as c:
            # B3: forged owner rows never make it into the owner list.
            return [
                PairingRecord(
                    channel=r["channel"],
                    channel_user_id=r["channel_user_id"],
                    user_handle=r["user_handle"] or "",
                    trust_level=r["trust_level"],
                    paired_at=float(r["paired_at"]),
                )
                for r in c.execute(q, args).fetchall()
                if _signature_ok(r)
            ]

    def all_pairings(self) -> list[PairingRecord]:
        with _conn() as c:
            rows = c.execute("SELECT * FROM pairings").fetchall()
            return [
                PairingRecord(
                    channel=r["channel"],
                    channel_user_id=r["channel_user_id"],
                    user_handle=r["user_handle"] or "",
                    trust_level=r["trust_level"],
                    paired_at=float(r["paired_at"]),
                )
                for r in rows
                if _signature_ok(r)
            ]

    def verify_pairings(self) -> dict:
        """B3, mirroring B2's verify_chain(): report rows whose signature does
        not verify, i.e. pairings written outside the signed path."""
        with _conn() as c:
            rows = c.execute("SELECT * FROM pairings").fetchall()
        if not config.pairing_signing_key():
            return {"ok": True, "signing": False, "rows": len(rows), "forged": []}
        forged = [
            {"channel": r["channel"], "channel_user_id": r["channel_user_id"], "trust_level": r["trust_level"]}
            for r in rows
            if not _signature_ok(r)
        ]
        return {"ok": not forged, "signing": True, "rows": len(rows), "forged": forged}

    def revoke(self, channel: str, channel_user_id: str) -> bool:
        with _conn() as c:
            cur = c.execute(
                "DELETE FROM pairings WHERE channel=? AND channel_user_id=?",
                (channel, channel_user_id),
            )
            return cur.rowcount > 0

    def force_pair_owner(
        self,
        channel: str,
        channel_user_id: str,
        user_handle: str = "owner",
        *,
        install_token: str | None = None,
    ) -> PairingRecord:
        """Out-of-band pairing for the installation owner, used by the
        installer to bootstrap the first owner identity.

        Finding B3: this grants the top trust level, so it now requires the
        install token — an installer capability. It used to be guarded only by
        a docstring saying "not exposed through HTTP", which is true and
        irrelevant: every adapter shares this process and could just call it.
        After B4 the gateway keeps only sha256(token), so in-process code
        cannot produce one.

        The token may be passed explicitly, or come from GLC_INSTALL_TOKEN for
        installer/setup scripts that run in their OWN process. That fallback is
        safe inside the gateway: seal_install_token() scrubs the variable at
        boot, and any value supplied still has to verify against the stored
        hash.

        Raises PairingPermissionError if the token is missing or wrong. Both
        the grant and the refusal are audited, so escalation is never silent.
        """
        from glc.audit import append as audit_append

        tok = install_token if install_token is not None else os.getenv(config.INSTALL_TOKEN_ENV)
        if not config.verify_install_token(tok):
            audit_append(
                channel=channel,
                channel_user_id=channel_user_id,
                trust_level="untrusted",
                event_type="force_pair_owner_denied",
                result={"reason": "missing or invalid install token"},
            )
            raise PairingPermissionError(
                "force_pair_owner requires the install token (installer capability): "
                "pass install_token=... or set GLC_INSTALL_TOKEN"
            )

        paired_at = time.time()
        with _conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO pairings
                   (channel, channel_user_id, user_handle, trust_level, paired_at, signature)
                   VALUES (?,?,?,?,?,?)""",
                (
                    channel,
                    channel_user_id,
                    user_handle,
                    "owner_paired",
                    paired_at,
                    _sign(channel, channel_user_id, user_handle, "owner_paired", paired_at),
                ),
            )
        audit_append(
            channel=channel,
            channel_user_id=channel_user_id,
            trust_level="owner_paired",
            event_type="force_pair_owner_granted",
            params={"user_handle": user_handle},
        )
        return PairingRecord(
            channel=channel,
            channel_user_id=channel_user_id,
            user_handle=user_handle,
            trust_level="owner_paired",
            paired_at=paired_at,
        )


_singleton: PairingStore | None = None


def get_pairing_store() -> PairingStore:
    global _singleton
    if _singleton is None:
        _singleton = PairingStore()
    return _singleton

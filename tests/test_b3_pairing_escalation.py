"""Session 12, finding B3 / leak 3 (in-process escalation to owner): an
adapter sharing the gateway process could crown itself owner two ways --

  1. call the installer's method, guarded only by a docstring:
       get_pairing_store().force_pair_owner("telegram", "attacker-id")
  2. skip the method and write the row, since pairings.sqlite is writable and
     lookup() trusted whatever trust_level it found.

Both are closed: the method requires the install token (which, after B4, the
gateway does not hold in recoverable form), and every pairing row is HMAC
signed so an unsigned row written straight into SQLite is inert.
"""

from __future__ import annotations

import sqlite3
import time

import pytest

import glc.config as config
import glc.security.pairing as pairing
from glc.security.pairing import PairingPermissionError, get_pairing_store
from tests.conftest import TEST_INSTALL_TOKEN


def _raw_db() -> sqlite3.Connection:
    """A raw handle on pairings.sqlite — leak 3's second exploit."""
    return sqlite3.connect(pairing._resolve_path())


def _insert_owner_row_directly(channel: str = "telegram", uid: str = "attacker-id") -> None:
    with _raw_db() as c:
        c.execute(
            """INSERT OR REPLACE INTO pairings
               (channel, channel_user_id, user_handle, trust_level, paired_at)
               VALUES (?,?,?,?,?)""",
            (channel, uid, "me", "owner_paired", time.time()),
        )
        c.commit()


# ── exploit 1: calling the installer method ─────────────────────────────────


def test_force_pair_owner_without_the_token_is_refused(monkeypatch):
    """The gateway scrubs GLC_INSTALL_TOKEN at boot, so this is what an
    in-process attacker actually faces."""
    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    store = get_pairing_store()

    with pytest.raises(PairingPermissionError):
        store.force_pair_owner("telegram", "attacker-id", user_handle="me")

    assert store.lookup("telegram", "attacker-id") is None


def test_force_pair_owner_with_a_wrong_token_is_refused(monkeypatch):
    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    store = get_pairing_store()

    with pytest.raises(PairingPermissionError):
        store.force_pair_owner("telegram", "attacker-id", install_token="not-the-token")

    assert store.lookup("telegram", "attacker-id") is None


def test_refusal_is_audited(monkeypatch):
    """Escalation attempts are never silent."""
    from glc.audit import query

    monkeypatch.delenv(config.INSTALL_TOKEN_ENV, raising=False)
    with pytest.raises(PairingPermissionError):
        get_pairing_store().force_pair_owner("telegram", "attacker-id")

    events = [r["event_type"] for r in query(limit=10)]
    assert "force_pair_owner_denied" in events


def test_installer_with_the_token_still_works():
    store = get_pairing_store()

    rec = store.force_pair_owner("telegram", "real-owner", install_token=TEST_INSTALL_TOKEN)

    assert rec.trust_level == "owner_paired"
    assert store.lookup("telegram", "real-owner").trust_level == "owner_paired"


def test_grant_is_audited():
    from glc.audit import query

    get_pairing_store().force_pair_owner("telegram", "real-owner", install_token=TEST_INSTALL_TOKEN)

    events = [r["event_type"] for r in query(limit=10)]
    assert "force_pair_owner_granted" in events


# ── exploit 2: writing the row directly (the bypass a gate alone would miss) ─


def test_directly_inserted_owner_row_is_inert():
    """The whole point of Option A: the row exists in SQLite, but it carries no
    valid signature, so it is not honoured as a pairing at all."""
    store = get_pairing_store()
    _insert_owner_row_directly()

    with _raw_db() as c:  # the row really is in the table
        assert c.execute("SELECT COUNT(*) FROM pairings").fetchone()[0] == 1

    assert store.lookup("telegram", "attacker-id") is None  # ...but inert
    assert store.owners(channel="telegram") == []
    assert store.all_pairings() == []


def test_forged_row_is_reported_by_verify_pairings():
    store = get_pairing_store()
    _insert_owner_row_directly()

    result = store.verify_pairings()

    assert result["ok"] is False
    assert result["signing"] is True
    assert result["forged"][0]["channel_user_id"] == "attacker-id"


def test_tampering_a_real_pairing_up_to_owner_is_caught():
    """Editing trust_level in place invalidates the signature, because the
    signature covers trust_level."""
    store = get_pairing_store()
    store.force_pair_owner("telegram", "victim", install_token=TEST_INSTALL_TOKEN)
    with _raw_db() as c:
        c.execute("UPDATE pairings SET channel_user_id='attacker' WHERE channel_user_id='victim'")
        c.commit()

    assert store.lookup("telegram", "attacker") is None
    assert store.verify_pairings()["ok"] is False


def test_legitimate_pairings_verify():
    store = get_pairing_store()
    store.force_pair_owner("telegram", "real-owner", install_token=TEST_INSTALL_TOKEN)

    result = store.verify_pairings()
    assert result["ok"] is True
    assert result["forged"] == []


# ── the honest, documented limits ───────────────────────────────────────────


def test_confirmed_code_pairing_is_signed_and_honoured():
    """The normal pairing flow still works end to end and produces a signed row."""
    store = get_pairing_store()
    code, _ = store.issue_code("telegram", "user-1", "handle", requested_trust_level="user_paired")

    rec = store.confirm_code(code)

    assert rec is not None
    assert store.lookup("telegram", "user-1").trust_level == "user_paired"
    assert store.verify_pairings()["ok"] is True


def test_unsigned_mode_when_the_process_never_saw_a_plaintext(monkeypatch):
    """No key -> no signing and no enforcement (local dev / legacy install).
    Documented, and why a real deployment supplies GLC_INSTALL_TOKEN."""
    monkeypatch.setattr(config, "_pairing_key", None)
    store = get_pairing_store()
    _insert_owner_row_directly()

    result = store.verify_pairings()
    assert result["signing"] is False
    assert result["ok"] is True  # nothing to verify against

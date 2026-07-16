"""Session 12, finding B2 / leak 2 (audit db writable at the OS layer): the
application layer only offers append(), but the SQLite file is writable by
any code in the gateway process, so `DELETE FROM audit_log` silently erased
the security history (invariant 7).

The log is now a hash chain anchored by audit_chain_head. These tests drive
the real tampering -- raw SQL against the same file an in-process attacker
would open -- and assert verify_chain() catches it.
"""

from __future__ import annotations

import sqlite3

import glc.audit.store as audit_store


def _tamper() -> sqlite3.Connection:
    """A raw handle on the audit db — exactly what leak 2's exploit uses."""
    return sqlite3.connect(audit_store._resolve_path())


def _append(n: int = 1) -> None:
    for i in range(n):
        audit_store.append(
            channel="telegram",
            channel_user_id="u1",
            trust_level="untrusted",
            event_type="inbound_message",
            params={"text": f"message {i}"},
        )


# ── the honest path ─────────────────────────────────────────────────────────


def test_empty_log_verifies():
    audit_store.init_store()
    assert audit_store.verify_chain()["ok"] is True


def test_appends_build_a_verifiable_chain():
    _append(3)
    result = audit_store.verify_chain()
    assert result["ok"] is True
    assert result["rows"] == 3


def test_each_row_links_to_its_predecessor():
    _append(2)
    with _tamper() as c:
        c.row_factory = sqlite3.Row
        rows = c.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    assert rows[0]["prev_hash"] == audit_store.GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[0]["row_hash"]


# ── the tampering the finding names ─────────────────────────────────────────


def test_detects_wholesale_delete():
    """Leak 2's exploit verbatim: DELETE FROM audit_log. An in-table chain
    alone would miss this (an empty table chains vacuously) -- the anchor is
    what catches it."""
    _append(3)
    with _tamper() as c:
        c.execute("DELETE FROM audit_log")
        c.commit()

    result = audit_store.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "rows_missing"
    assert result["expected_rows"] == 3
    assert result["rows"] == 0


def test_detects_deletion_of_a_single_row():
    """Quietly removing one incriminating event breaks the linkage."""
    _append(3)
    with _tamper() as c:
        c.execute("DELETE FROM audit_log WHERE id=2")
        c.commit()

    result = audit_store.verify_chain()
    assert result["ok"] is False
    assert result["reason"] in ("chain_broken", "rows_missing")


def test_detects_row_modification():
    """Rewriting history in place: the row no longer hashes to its row_hash."""
    _append(3)
    with _tamper() as c:
        c.execute("UPDATE audit_log SET event_type='harmless' WHERE id=2")
        c.commit()

    result = audit_store.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "row_modified"
    assert result["broken_at"] == 2


def test_detects_truncation_of_the_newest_rows():
    """Dropping the tail (the most recent, most incriminating events)."""
    _append(3)
    with _tamper() as c:
        c.execute("DELETE FROM audit_log WHERE id=3")
        c.commit()

    result = audit_store.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "rows_missing"


def test_detects_dropped_table():
    """DROP TABLE is reported, not raised."""
    _append(1)
    with _tamper() as c:
        c.execute("DROP TABLE audit_log")
        c.commit()

    result = audit_store.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "table_missing"


def test_forged_row_without_the_chain_is_caught():
    """An attacker inserting a fabricated event straight into the table --
    without knowing how to extend the chain -- is caught."""
    _append(2)
    with _tamper() as c:
        c.execute(
            """INSERT INTO audit_log
               (ts, channel, channel_user_id, trust_level, event_type, row_hash, prev_hash)
               VALUES (1.0, 'telegram', 'attacker', 'owner_paired', 'forged', 'deadbeef', 'deadbeef')"""
        )
        c.commit()

    assert audit_store.verify_chain()["ok"] is False


# ── the chain keeps working afterwards ──────────────────────────────────────


def test_appends_still_verify_after_many_writes():
    _append(10)
    result = audit_store.verify_chain()
    assert result["ok"] is True
    assert result["rows"] == 10


def test_query_still_returns_rows():
    """The chain must not disturb the existing read path."""
    _append(2)
    assert len(audit_store.query(limit=10)) == 2


def test_schema_is_at_v2():
    audit_store.init_store()
    assert audit_store.schema_version() == 2


def test_v1_database_migrates_to_v2(monkeypatch, tmp_path):
    """A live deployment already has a v1 audit_log on the Volume. It must
    gain the chain columns, and its pre-migration rows must be reported as
    `legacy_rows` -- unverifiable, but not mistaken for tampering."""
    db = tmp_path / "v1.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db))

    c = sqlite3.connect(str(db))
    c.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL, session_id TEXT, channel TEXT NOT NULL,
            channel_user_id TEXT NOT NULL, trust_level TEXT NOT NULL,
            event_type TEXT NOT NULL, tool TEXT, policy_verdict TEXT,
            params_json TEXT, result_json TEXT
        );
        INSERT INTO audit_log (ts, channel, channel_user_id, trust_level, event_type)
        VALUES (1.0, 'telegram', 'u', 'untrusted', 'legacy_event');
        """
    )
    c.commit()
    c.close()

    audit_store.init_store()  # runs the v1 -> v2 migration

    result = audit_store.verify_chain()
    assert result["ok"] is True  # a legacy row is not a chain failure
    assert result["legacy_rows"] == 1
    assert result["rows"] == 0

    # new rows chain normally on top of the legacy tail
    _append(1)
    after = audit_store.verify_chain()
    assert after["ok"] is True
    assert after["rows"] == 1
    assert after["legacy_rows"] == 1

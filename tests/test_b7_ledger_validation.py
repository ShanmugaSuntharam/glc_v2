"""Session 12, finding B7 (cost-ledger poisoning): glc.db.log_call() wrote
whatever the caller supplied, validating nothing, so any code sharing the
gateway process could poison the ledger behind /v1/cost/by_agent.

These tests pin the validation at that chokepoint: absurd, negative, and
non-integer counters are refused; realistic rows still land unchanged.
"""

from __future__ import annotations

import pytest

import glc.db as db


@pytest.fixture(autouse=True)
def _isolated_ledger(monkeypatch, tmp_path):
    """db.DB_PATH is resolved at import time, so point it at a temp file
    explicitly rather than relying on the env var."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "gateway.sqlite"))
    db.init()


def _ok(**overrides):
    """A realistic worker call."""
    kwargs = dict(
        provider="gemini",
        model="gemini-2.5-flash",
        input_tokens=1200,
        output_tokens=340,
        latency_ms=850,
        status="ok",
        agent="researcher",
    )
    kwargs.update(overrides)
    return kwargs


# ── the row a legitimate caller writes still works ──────────────────────────


def test_realistic_call_is_recorded():
    db.log_call(**_ok())
    rows = db.recent(limit=1)
    assert rows[0]["provider"] == "gemini"
    assert rows[0]["input_tokens"] == 1200
    assert rows[0]["agent"] == "researcher"


def test_none_counter_is_treated_as_zero():
    """chat.py passes result.get("input_tokens", 0), which can be None."""
    db.log_call(**_ok(input_tokens=None, output_tokens=None))
    assert db.recent(limit=1)[0]["input_tokens"] == 0


def test_embed_dim_stays_nullable():
    db.log_call(**_ok(call_role="embed", embed_dim=None))
    assert db.recent(limit=1)[0]["embed_dim"] is None


# ── the poisoning the finding names ─────────────────────────────────────────


def test_absurd_token_count_is_refused():
    """The notes' exploit: input_tokens=999_999_999 to inflate a victim's spend."""
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(input_tokens=999_999_999, agent="victim"))
    assert db.recent(limit=1) == []  # nothing was written


def test_negative_token_count_is_refused():
    """Worse than inflation: a negative shrinks SUM() in by_agent()/aggregate(),
    masking real spend."""
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(input_tokens=-5_000_000))
    assert db.recent(limit=1) == []


def test_non_integer_counter_is_refused():
    """SQLite is dynamically typed, so a string would land in the INTEGER
    column and corrupt every later SUM/AVG over it."""
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(input_tokens="999999999"))
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(output_tokens=1.5))
    assert db.recent(limit=1) == []


def test_bool_counter_is_refused():
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(tool_calls=True))


def test_provider_and_model_are_required():
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(provider=None))
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(model=""))


def test_oversized_text_is_bounded_not_stored_whole():
    """A caller must not be able to fill the ledger with giant blobs."""
    db.log_call(**_ok(error="A" * 100_000))
    assert len(db.recent(limit=1)[0]["error"]) == db.MAX_TEXT_LEN


def test_refused_row_does_not_corrupt_later_totals():
    """A rejected poisoning attempt leaves the real aggregates intact."""
    db.log_call(**_ok(input_tokens=100))
    with pytest.raises(db.LedgerValueError):
        db.log_call(**_ok(input_tokens=999_999_999, agent="victim"))
    db.log_call(**_ok(input_tokens=200))

    totals = db.by_agent()
    assert totals["researcher"][0]["in_tok"] == 300  # 100 + 200, poison excluded

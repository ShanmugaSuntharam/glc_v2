"""Session 12, finding A6 (audit db on a Volume with autoscale): the audit
trail must be a single-writer, durable log. The container-count cap
(max_containers=1) is a Modal deploy setting (see modal_app.py); these
tests cover the in-code half — the Volume-commit hook that makes each
append durable — and the app-layer append-only property (invariant 7).
"""

from __future__ import annotations

import glc.audit.store as audit_store


def _append_one() -> int:
    return audit_store.append(
        channel="telegram",
        channel_user_id="u1",
        trust_level="untrusted",
        event_type="inbound_message",
    )


def test_append_runs_the_commit_hook():
    """A6: under Modal each append must flush to the Volume via the hook."""
    calls: list[int] = []
    audit_store.set_commit_hook(lambda: calls.append(1))

    rowid = _append_one()

    assert rowid > 0
    assert calls == [1], "append must invoke the volume-commit hook exactly once"


def test_append_works_with_no_hook():
    """Off Modal (local dev / tests) the hook is unset and append is a plain
    durable SQLite write."""
    audit_store.set_commit_hook(None)
    assert _append_one() > 0


def test_commit_hook_failure_never_breaks_append():
    """A volume-commit hiccup must not fail the request path or block
    auditing -- the row is already written; the commit is best-effort."""
    def boom() -> None:
        raise RuntimeError("volume unavailable")

    audit_store.set_commit_hook(boom)

    rowid = _append_one()  # must not raise
    assert rowid > 0
    # and the row really landed
    rows = audit_store.query(limit=1)
    assert rows and rows[0]["event_type"] == "inbound_message"


def test_store_is_append_only_at_the_app_layer():
    """Invariant 7: the store exposes no way to update or delete rows."""
    assert not hasattr(audit_store.AuditStore, "delete")
    assert not hasattr(audit_store.AuditStore, "update")
    assert not hasattr(audit_store.AuditStore, "clear")

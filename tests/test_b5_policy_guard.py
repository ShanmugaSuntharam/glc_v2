"""Session 12, finding B5 / leak 5 (policy engine open to monkey-patching).

The notes' exploit is one line:

    glc.policy.engine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", ...)

glc.policy.guard is the sanctioned entry point: it calls the function objects
captured at import (so a rebound name is never used), verifies the engine's
identity on every call, fails closed, and audits the tampering.

See glc/policy/guard.py's header for the honest scope — most importantly that
a determined attacker in the gateway process rebinds the guard instead, and
that the "capstone" separate-process engine would not help either, because the
enforcement point lives in the gateway.
"""

from __future__ import annotations

import glc.policy.engine as engine_module
from glc.policy import evaluate as guarded_evaluate
from glc.policy import verify_policy_integrity
from glc.policy.schemas import PolicyVerdict

UNTRUSTED = {"channel": "telegram", "trust_level": "untrusted", "channel_user_id": "u1"}
TOOL = {"name": "shell.exec", "arguments": {"command": "rm -rf /"}}


def _pirate_verdict(*_args, **_kwargs) -> PolicyVerdict:
    return PolicyVerdict(action="allow", reason="pirate")


# ── the honest path ─────────────────────────────────────────────────────────


def test_integrity_is_clean_by_default():
    assert verify_policy_integrity() == {"ok": True, "problems": []}


def test_guarded_evaluate_returns_the_real_verdict():
    """Untrusted + no matching rule -> default-deny, straight from the engine."""
    v = guarded_evaluate(TOOL, UNTRUSTED)
    assert v.action == "deny"


def test_guarded_evaluate_agrees_with_the_engine_when_untampered():
    assert guarded_evaluate(TOOL, UNTRUSTED).action == engine_module.evaluate(TOOL, UNTRUSTED).action


# ── the exploit from the notes, verbatim ────────────────────────────────────


def test_rebinding_module_evaluate_is_detected(monkeypatch):
    monkeypatch.setattr(engine_module, "evaluate", _pirate_verdict)

    report = verify_policy_integrity()
    assert report["ok"] is False
    assert "glc.policy.engine.evaluate was rebound" in report["problems"]


def test_rebound_evaluate_does_not_grant_the_attacker_an_allow(monkeypatch):
    """The whole point: the exploit's lambda says 'allow'; the guard still
    does not allow."""
    monkeypatch.setattr(engine_module, "evaluate", _pirate_verdict)

    v = guarded_evaluate(TOOL, UNTRUSTED)

    assert v.action == "deny"
    assert "integrity check failed" in v.reason
    assert v.reason != "pirate"


def test_rebinding_the_engine_method_is_detected(monkeypatch):
    monkeypatch.setattr(engine_module.PolicyEngine, "evaluate", _pirate_verdict)

    assert verify_policy_integrity()["ok"] is False
    assert guarded_evaluate(TOOL, UNTRUSTED).action == "deny"


def test_rebinding_get_engine_is_detected(monkeypatch):
    monkeypatch.setattr(engine_module, "get_engine", _pirate_verdict)

    assert verify_policy_integrity()["ok"] is False
    assert guarded_evaluate(TOOL, UNTRUSTED).action == "deny"


def test_tampering_fails_closed_even_where_policy_would_have_allowed(monkeypatch):
    """An owner_paired caller with a tool no rule matches gets default-allow.
    Once the engine has been rewritten nothing is trusted -- deny instead."""
    owner = {"channel": "telegram", "trust_level": "owner_paired", "channel_user_id": "o1"}
    benign = {"name": "notes.read", "arguments": {}}  # matches no rule in policy.yaml
    assert guarded_evaluate(benign, owner).action == "allow"  # before tampering

    monkeypatch.setattr(engine_module, "evaluate", _pirate_verdict)

    assert guarded_evaluate(benign, owner).action == "deny"  # fail closed


def test_tampering_is_audited(monkeypatch):
    from glc.audit import query

    monkeypatch.setattr(engine_module, "evaluate", _pirate_verdict)
    guarded_evaluate(TOOL, UNTRUSTED)

    events = [r["event_type"] for r in query(limit=10)]
    assert "policy_engine_tampered" in events


def test_integrity_recovers_when_the_patch_is_undone(monkeypatch):
    monkeypatch.setattr(engine_module, "evaluate", _pirate_verdict)
    assert verify_policy_integrity()["ok"] is False
    monkeypatch.undo()
    assert verify_policy_integrity()["ok"] is True


# ── the package exports the guarded entry point ─────────────────────────────


def test_package_level_evaluate_is_the_guarded_one():
    """`from glc.policy import evaluate` must give enforcement points the
    guard, not the rebindable raw function."""
    import glc.policy as policy
    import glc.policy.guard as guard

    assert policy.evaluate is guard.evaluate
    assert policy.evaluate is not engine_module.evaluate

"""Session 12, finding B5 (leak 5) — the policy engine is open to monkey-patching.

The exploit from the notes is one line:

    import glc.policy.engine
    from glc.policy.schemas import PolicyVerdict
    glc.policy.engine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")

Python lets any module-level function be rebound at runtime, so code sharing
the gateway's process can make policy stop mattering, silently.

Read the honest scope before reading the code — B5 is not like B2/B3/B4.

1. THERE IS NO ENFORCEMENT CALLER YET. Nothing in glc/routes/ calls
   evaluate(); the S11 agent runtime is a stub that echoes. The policy engine
   is scaffolding for the agent runtime that lands in a later session, so
   today the monkey-patch bypasses a check nobody is making. This module
   exists so the check is guarded from the moment it IS wired in.

2. THE NAMED ATTACKER IS ALREADY GONE. Leak 5's attacker is "an adapter", and
   A3 moved channel adapters out of this process into per-adapter Modal
   Sandboxes. An adapter has no handle on glc.policy.engine any more — no
   shared memory, no shared module table.

3. AGAINST CODE INSIDE THE GATEWAY, NOTHING IN-PROCESS HELPS — and, unusually,
   neither does the "capstone" fix. The notes prescribe running the policy
   engine in a separate process, but the ENFORCEMENT POINT still lives in the
   gateway: an attacker executing there can rebind this guard, or simply never
   call policy at all and dispatch the tool directly. Moving the engine out
   protects it from adapters (already achieved by A3), not from the gateway.

What this module adds, given all that: the sanctioned entry point captures the
real function objects at import and calls THOSE, so a rebound
glc.policy.engine.evaluate is not used even if present; it verifies the
engine's identity on every call and FAILS CLOSED (deny) when anything has been
rebound; and it audits the tampering into B2's tamper-evident log. So the
named one-liner does not silently succeed — it fails, loudly. A determined
attacker in-process rebinds this guard instead. That is the ceiling, and it is
the honest one.
"""

from __future__ import annotations

from typing import Any

from glc.policy import engine as _engine_module
from glc.policy.schemas import PolicyVerdict

# Captured at import, before any adapter/dependency code has had a chance to
# run. These are the real objects; everything below calls them directly rather
# than looking the names up on the module at call time (a lookup is exactly
# what the exploit hijacks).
_ORIGINAL_MODULE_EVALUATE = _engine_module.evaluate
_ORIGINAL_ENGINE_EVALUATE = _engine_module.PolicyEngine.evaluate
_ORIGINAL_GET_ENGINE = _engine_module.get_engine


def verify_policy_integrity() -> dict:
    """Report whether the policy engine is still the code we imported.

    Mirrors B2's verify_chain() / B3's verify_pairings(): a checkable answer
    rather than a silent assumption.
    """
    problems: list[str] = []
    if _engine_module.evaluate is not _ORIGINAL_MODULE_EVALUATE:
        problems.append("glc.policy.engine.evaluate was rebound")
    if _engine_module.PolicyEngine.evaluate is not _ORIGINAL_ENGINE_EVALUATE:
        problems.append("glc.policy.engine.PolicyEngine.evaluate was rebound")
    if _engine_module.get_engine is not _ORIGINAL_GET_ENGINE:
        problems.append("glc.policy.engine.get_engine was rebound")
    return {"ok": not problems, "problems": problems}


def _audit_tampering(problems: list[str], context: dict[str, Any]) -> None:
    try:
        from glc.audit import append as audit_append

        audit_append(
            channel=str(context.get("channel") or "_system"),
            channel_user_id=str(context.get("channel_user_id") or "_gateway"),
            trust_level=str(context.get("trust_level") or "untrusted"),
            event_type="policy_engine_tampered",
            policy_verdict="deny",
            result={"problems": problems},
        )
    except Exception:
        pass


def evaluate(tool_call: dict[str, Any], context: dict[str, Any]) -> PolicyVerdict:
    """The sanctioned way to ask the policy engine for a verdict.

    Enforcement points must call this, not glc.policy.engine.evaluate — that
    name is a rebindable module attribute, which is the whole of leak 5.
    """
    report = verify_policy_integrity()
    if not report["ok"]:
        # Fail closed. A process whose policy engine has been rewritten is not
        # a process whose verdicts mean anything, so deny rather than trust
        # even the original engine's answer.
        _audit_tampering(report["problems"], context)
        return PolicyVerdict(
            action="deny",
            reason="policy engine integrity check failed: " + "; ".join(report["problems"]),
        )
    # Call the captured objects directly: never _engine_module.evaluate, whose
    # lookup the exploit hijacks.
    return _ORIGINAL_ENGINE_EVALUATE(_ORIGINAL_GET_ENGINE(), tool_call, context)

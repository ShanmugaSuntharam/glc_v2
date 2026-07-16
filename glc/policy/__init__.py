"""Policy engine package.

Session 12, finding B5: the package-level `evaluate` is the GUARDED entry
point (glc.policy.guard.evaluate), not the raw module function. Enforcement
points should use `from glc.policy import evaluate` so they get the integrity
check and fail-closed behaviour by default. `glc.policy.engine.evaluate`
remains importable as the raw, unguarded function — the guard itself and the
engine's own unit tests use it.
"""

from glc.policy.engine import PolicyEngine, get_engine, reload_engine
from glc.policy.guard import evaluate, verify_policy_integrity
from glc.policy.schemas import PolicyRule, PolicyVerdict

__all__ = [
    "PolicyEngine",
    "PolicyRule",
    "PolicyVerdict",
    "evaluate",
    "get_engine",
    "reload_engine",
    "verify_policy_integrity",
]

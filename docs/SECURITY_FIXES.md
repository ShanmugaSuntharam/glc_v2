# Security fixes (Session 12 — Part 1)

Running notes for the findings closed in this clone. Each entry names the
security **invariant** (Section 4 of the class notes) it restores, the
attacker role that reached it, and how the fix was verified.

Prior findings (A1 public data plane, A2 info-disclosure endpoints, A3
per-adapter Modal Sandboxes with an egress allowlist) are recorded in their
commit messages; this file starts the durable log at A4.

---

## A4 — One Secret for the whole Function (leak 1)

**Invariant restored:** 1 — *adapters must never see provider API keys*
(shared-process environment vector).
**Attacker role:** 3–4 — a compromised adapter / any code executing in the
gateway process (a poisoned dependency, agent-generated code, or an
SSRF→RCE foothold).

**The bug.** Move 1 delivered all provider keys through a single Modal
Secret (`glc-llm-keys`) mounted on the whole gateway Function, so every key
sat in `os.environ` for the container's lifetime. Any line of in-process
code could read all seven with one call — the Section-2 theft:

```python
os.environ["GEMINI_API_KEY"]   # returns the key, and so does every other
```

**The fix (option B — vault + per-provider Secrets).**

1. `glc/security/keyvault.py` — a single narrow accessor. At gateway
   startup `glc.main`'s lifespan calls `keyvault.seal()`, which snapshots
   each provider key into a private in-process store and **deletes it from
   `os.environ`**. Afterwards `os.getenv("GEMINI_API_KEY")` is `None` and
   `/proc/self/environ` no longer carries the secret.
2. `glc/providers.py` and `glc/embedders.py` read provider keys via
   `keyvault.get(...)` instead of `os.getenv(...)` — the only legitimate
   readers, now going through one auditable chokepoint.
3. `modal_app.py` splits `glc-llm-keys` into per-provider Secrets
   (`glc-provider-gemini`, `-nvidia`, `-groq`, `-cerebras`, `-openrouter`,
   `-github`), removing the single-Secret shape and letting each key be
   scoped and rotated on its own.

**Verified.** `tests/test_a4_keyvault.py`: after `seal()`, every registered
provider key is absent from `os.environ` while `keyvault.get()` and
`build_providers()` still resolve it; non-secret config (model names, URLs)
is never scrubbed; the accessor refuses non-provider names.

**Scope / what remains.** Option B closes the "all keys resident in the
environment, forever, for everything" blast radius and the single-Secret
shape. It does not, by itself, stop *trusted* in-gateway code from calling
`keyvault.get()`. The full completion (Moves 2–4 / option A) runs each
provider call in its own short-lived Modal Sandbox that receives only that
one provider's Secret with an egress allowlist — capstone scope, mirroring
what A3 already did for channel adapters.

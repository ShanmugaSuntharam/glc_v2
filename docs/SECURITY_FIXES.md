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

---

## C2 — Cross-channel envelope spoofing (leak 9)

**Invariant restored:** 2 — *every action must be checked against the
actual user, tenant, and final arguments* (here: the actual channel).
**Attacker role:** 3 — a compromised adapter holding the install token.

**The bug.** `WS /v1/channels/{name}` validated the incoming
`ChannelMessage` but never checked that `env.channel` matched the route
`{name}`. A Telegram adapter could connect to `/v1/channels/telegram` and
send an envelope with `env.channel="discord"`; every downstream check
(allowlist, owner pairing, audit) then ran against **discord**, so the
Telegram adapter borrowed Discord's trust.

**The fix.** `glc/routes/channels.py` — immediately after envelope
validation, reject any message whose `env.channel != name`: record a
`channel_spoof_rejected` audit event, send a `channel mismatch` error, and
close the socket (`WS_1008_POLICY_VIOLATION`). One deterministic
application-layer check, exactly as the notes prescribe.

**Verified.** `tests/test_c2_channel_spoof.py`: a mismatched envelope is
rejected and the socket closed; a matching envelope is not treated as a
spoof and the connection stays open.

**Also reviewed.** The `POST /v1/channels/{name}/webhook` path derives
`msg.channel` from adapter output; enforcing `msg.channel == name` there
too is a reasonable follow-up hardening, but the named leak 9 is the WS
control plane fixed here.

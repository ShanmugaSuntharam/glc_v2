# Security fixes (Session 12 — Part 1)

Running notes for the findings closed in this clone. Each entry names the
security **invariant** (Section 4 of the class notes) it restores, the
attacker role that reached it, and how the fix was verified.

Prior findings (A1 public data plane, A2 info-disclosure endpoints, A3
per-adapter Modal Sandboxes with an egress allowlist) are recorded in their
commit messages; this file starts the durable log at A4.

---

## A4 — One Secret for the whole Function (leak 1; also closes B1)

**Invariant restored:** 1 — *adapters must never see provider API keys*
(shared-process environment vector).
**Attacker role:** 3–4 — a compromised adapter / any code executing in the
gateway process (a poisoned dependency, agent-generated code, or an
SSRF→RCE foothold).

**Also closes B1.** B1 in the Section-7 in-process leak list *is* this same
vulnerability — the notes label it "env holds all keys (=A4)": all provider
keys readable from `os.environ` by any code sharing the gateway process.
The fix below is what closes it: after `keyvault.seal()`,
`os.getenv("GEMINI_API_KEY")` (and `/proc/self/environ`) no longer yield the
key in-process, so the B1 read fails too. One fix, both findings — A4 (the
Modal single-Secret shape) and B1 (the in-process env read).

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

---

## A5 — Non-reproducible image (supply-chain drift)

**Invariant restored:** supports the supply-chain posture behind all eight
(a build you cannot reproduce is a build you cannot trust or audit).
**Attacker role:** supply-chain — anyone who can influence what the base
image or a dependency resolves to between builds.

**The bug.** The image was built on the rolling `debian_slim` tag with
`>=` dependency ranges (`fastapi>=0.110`, …), re-resolved on every build
and ignoring `uv.lock`. Two identical `modal deploy` runs could ship
different bytes — a new base layer or a newer transitive dependency —
so a compromised upstream release lands silently, and nothing is
auditable or reproducible.

**The fix (build from pinned inputs).**

1. `requirements.lock.txt` — the fully pinned, hash-verified export of
   `uv.lock` (`uv export --frozen --no-dev --no-emit-project`): exact `==`
   versions with `--hash=` for the whole transitive closure. `modal_app.py`
   installs from it via `.pip_install_from_requirements(...)` instead of
   `.pip_install("pkg>=x")`, so pip runs in hash-verified mode.
2. `modal_app.py` — the base image is pinned to an immutable digest,
   `python:3.11-slim-bookworm@sha256:b189929…`, via
   `Image.from_registry(...)` instead of the rolling `debian_slim`.

Because `build_image()` is reused for every A3 per-adapter Sandbox too,
both the gateway Function and every Sandbox now build from identical,
pinned inputs.

**Verified.** `requirements.lock.txt` is fully pinned + hashed (1352
lines, no unpinned specs); the base digest was resolved from the Docker
Hub registry manifest; `uv run modal deploy` rebuilds the image from the
lock + digest and the gateway boots (`/healthz` → `{"ok": true}`).

**Maintenance.** After any dependency change, regenerate the lock export
and (when bumping the base) refresh the digest — both commands are in the
`modal_app.py` header comment.

---

## A6 — Audit db on a Volume with autoscale (concurrent writers + durability)

**Invariant restored:** 7 — *components must not be able to corrupt the
audit log* (here: the deployment must not corrupt it either).
**Attacker role:** availability / integrity — triggered by load, not a
specific actor: enough traffic makes autoscale spin up a second writer.

**The bug.** The audit / pairing / cost databases are SQLite files on the
shared Modal Volume. SQLite is single-writer and a Volume is not a
concurrent-write filesystem, yet the gateway ran with `min_containers=0`
and no upper bound — so under load Modal could run two containers, both
writing `audit.sqlite`, corrupting or splitting the trail. Separately, a
write to a Volume mount is not durable until the Volume is committed, and
the app never committed — so on scale-to-zero the newest audit rows could
vanish.

**The fix (single writer + explicit durability).**

1. `modal_app.py` — `max_containers=1` on the gateway Function. With
   `min=0 / max=1` there are only ever 0 or 1 writers, never two, so the
   concurrent-writer corruption cannot happen (this also protects the
   pairing and cost SQLite files on the same Volume).
2. `glc/audit/store.py` — a `set_commit_hook()` seam; `AuditStore.append()`
   flushes via the hook after every insert. `modal_app.py` registers
   `data_volume.commit`, so each audit row is persisted all the way to the
   Volume and survives shutdown / scale-to-zero. The hook is best-effort
   (a commit hiccup never fails the request or blocks auditing) and unset
   off Modal, where SQLite autocommit is already durable. `reload()` is
   unnecessary under `max_containers=1` — no other writer can advance the
   Volume behind the single container.

The store remains append-only at the app layer (no update/delete/clear
methods) — invariant 7.

**Verified.** `tests/test_a6_audit_durability.py`: append invokes the
commit hook exactly once; append still works with no hook; a failing hook
never breaks append and the row still lands; the store exposes no
delete/update/clear. Full suite 285 passed. Live: `uv run modal deploy`
with `max_containers=1` boots (`/healthz` → `{"ok": true}`).

**Scope / related.** The OS-layer writability of the SQLite files from
in-process code (leak 2 / B2: `DELETE FROM audit_log`) is a separate
finding — closed by component separation + a hash-chained append-only log,
tracked elsewhere. A6 is the deployment-level concurrency + durability of
the audit db, fixed here.

---

## B7 — Cost-ledger poisoning (leak 10)

**Invariant restored:** 8 — *every run must have hard limits on time,
tokens, tool calls, and cost*. A budget is only as trustworthy as the
ledger it is measured from; a ledger anyone can forge enforces nothing.
**Attacker role:** 3–4 — any code sharing the gateway process.

**The bug.** `glc.db.log_call()` wrote whatever the caller handed it and
validated nothing, so in-process code could forge rows in the ledger that
`/v1/cost/by_agent`, `recent()` and `aggregate()` report from:

```python
glc.db.log_call(provider="gemini", model="x",
                input_tokens=999_999_999, agent="victim", status="ok")
```

Three concrete harms:
* **absurd counters** inflate a victim's apparent spend (the notes' exploit);
* **negative counters** are worse — they *shrink* the `SUM()` in
  `by_agent()`/`aggregate()`, so an attacker can **mask** real spend rather
  than merely fake it;
* **non-integer values** slide straight into an `INTEGER` column (SQLite is
  dynamically typed), corrupting every later `SUM`/`AVG` over it.

**The fix.** `glc/db.py` validates every field at the single write
chokepoint before it reaches the ledger:
* each counter must be a **non-negative whole number within a ceiling** set
  far above any real call (`MAX_TOKENS` 10M vs. ~2M largest real context;
  `MAX_LATENCY_MS` 24h);
* text fields are **length-bounded** (`MAX_TEXT_LEN`) so a caller cannot
  fill the ledger/Volume with giant blobs;
* `provider` / `model` are required and non-empty.

A bad row is **refused** (`LedgerValueError`), not clamped — clamping would
still record the attacker's fiction, just a smaller one. `None` counters
still coerce to `0` because the real callers pass
`result.get("input_tokens", 0)`, which can be `None`.

**Verified.** `tests/test_b7_ledger_validation.py` (10 tests): the absurd,
negative, non-integer and bool counters are all refused and nothing is
written; realistic rows still land; `None`→0 and nullable `embed_dim`
preserved; oversized text bounded; and a refused poisoning attempt leaves
`by_agent()` totals intact. Full suite 295 passed — all 11 legitimate
`log_call` sites in `glc/routes/chat.py` unaffected.

**Honest scope.** This does **not** stop a caller writing *plausible* fake
rows, or attributing a genuine call to another agent — those numbers pass
every check here. Closing that needs a signed writer the gateway alone
holds, plus process separation (capstone scope, same root cause as B5/B6:
one process, no walls).

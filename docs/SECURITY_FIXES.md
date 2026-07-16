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

---

## B2 — Audit db writable at the OS layer (leak 2)

**Invariant restored:** 7 — *components must not be able to edit or delete
their own audit logs*.
**Attacker role:** 3–4 — any code sharing the gateway process.

**The bug.** The application layer exposed only `append()` — no update, no
delete — but that is a promise made in Python, not one the filesystem
enforces. The audit db is a plain SQLite file, writable by anything running
as the same user, which is every adapter:

```python
sqlite3.connect("~/.glc/audit.sqlite").execute("DELETE FROM audit_log")
```

The security history is gone, silently, with nothing left to show it ever
existed.

**The fix (tamper-evident hash chain + anchor).** Schema **v1 → v2**:

1. `glc/audit/schema.sql` — `audit_log` gains `prev_hash` / `row_hash`, and
   a new one-row `audit_chain_head` table anchors the expected head hash and
   row count.
2. `glc/audit/store.py` — `append()` now reads the head, computes
   `row_hash = sha256(prev_hash + every field of the row)`, inserts the
   chained row and advances the anchor — all inside one `BEGIN IMMEDIATE`
   transaction under a process lock, so the anchor can never drift from the
   table or fork under concurrent appends.
3. `verify_chain()` recomputes the whole chain and reports precisely what
   went wrong: `row_modified`, `chain_broken`, `rows_missing`,
   `head_mismatch`, or `table_missing`.
4. `_migrate()` ALTERs a live v1 `audit_log` up to v2 (`CREATE TABLE IF NOT
   EXISTS` cannot add columns to an existing table). Pre-migration rows keep
   NULL hashes and are reported as `legacy_rows` — unverifiable, but not
   mistaken for tampering.

**Why the anchor matters.** A hash chain *inside* the table cannot detect a
wholesale `DELETE FROM audit_log` — an empty table chains vacuously. The
anchor is what catches it: the rows are gone, but the head still remembers
how many there should have been.

**Verified.** `tests/test_b2_audit_chain.py` (13 tests) drives the real
exploit — raw `sqlite3.connect()` against the same file, exactly as leak 2
does — and asserts detection of: the wholesale `DELETE` (the named exploit),
a single-row deletion, an in-place row modification, tail truncation, a
`DROP TABLE`, and a forged row inserted without extending the chain. Plus
the honest path (chain verifies, rows link, `query()` unaffected) and the
v1→v2 migration. Full suite 308 passed.

**Honest scope.** This makes tampering **detectable, not impossible**. The
hash is unkeyed and the anchor lives in the same file, so in-process code
can still delete rows *and* recompute the chain and anchor to match. What it
closes is the naive erase the finding names, and it makes any tampering that
does not also forge the chain loudly visible. Tamper-*proof* needs the
writer in its own process holding a key the caller cannot reach, or an
external anchor — same root cause as B5/B6.

---

## B4 — Install token readable in-process (leak 4)

**Invariant restored:** supports 1/2 — the control token is the operator's
identity; anything holding it can act as the operator.
**Attacker role:** 3–4 — any code sharing the gateway process.

**The bug.** The per-installation control token sat on disk in **plaintext**
at `~/.glc/install_token`, mode `0600`. Mode `0600` keeps other *Unix users*
out — it does nothing about other *code running as the same user*, which is
every adapter in the gateway process:

```python
tok = open(os.path.expanduser("~/.glc/install_token")).read().strip()
```

One line, and the caller holds the operator's credential.

**The fix (store a verifier, not a secret).** The gateway never needs to
*recover* the token — only to *verify* a presented one. So only
`sha256(token)` is kept, on disk and in memory. Reading the file now yields a
hash, which is useless as a bearer credential.

`glc/config.py` resolves the token once at boot via `seal_install_token()`,
from, in priority order:
1. **`GLC_INSTALL_TOKEN`** (env / Modal Secret) — the operator picks it, so
   they already know it and nothing ever has to hand it back. Scrubbed from
   `os.environ` on seal, so `os.getenv()` is closed too (same move as A4).
2. **A legacy plaintext file** — hashed **in place** on first boot, so an
   existing installation's token keeps working while the plaintext leaves
   disk.
3. **Freshly generated** — returned exactly once so the operator can record
   it; only the hash is retained.

Verification uses `hmac.compare_digest`, so the check is also no longer a
**timing oracle** (Category 11) that could leak the token a character at a
time. `glc token --rotate` mints a new token if the operator loses theirs.
Consumers that used to *steal* the token from disk — the twilio_sms webhook
and the telegram/discord dev bridges — are now *given* one via
`GLC_INSTALL_TOKEN`, which is what an adapter should always have done.

**Verified.** `tests/test_b4_install_token.py` (11 tests): the disk holds a
hash not the token, and presenting that stolen hash to the data plane and the
WS route both fail (403 / socket closed) — the end-to-end version of leak 4;
the env var is scrubbed after seal; a legacy plaintext file migrates in place
with the old token still valid; fresh install shows the token once and never
persists it; rotation invalidates the old token. Full suite 319 passed.

**Honest scope.** Verification-only storage means there is no on-disk or
in-environment copy to steal. It does not stop in-process code from reading a
token off a request in flight, or from using `verify_install_token()` as an
oracle (guessing a 256-bit token is infeasible). Binding the token to the
gateway alone is, as the notes say, ultimately process separation.

**⚠ Deployment note.** `modal_app.py` now attaches a `glc-install-token`
Secret. Create it before the next deploy:
```
uv run modal secret create glc-install-token GLC_INSTALL_TOKEN=<pick-a-strong-value>
```
If you instead let the existing Volume token migrate, **save your current
token first** — after the migration it is a hash and cannot be recovered
(recover by rotating).

---

## B3 — In-process escalation to owner (leak 3)

**Invariant restored:** 2 — *every action must be checked against the actual
user*. `owner_paired` is the top trust level; granting it to yourself defeats
every allowlist downstream.
**Attacker role:** 3–4 — any code sharing the gateway process.

**The bug — two doors, not one.** `force_pair_owner()` is an installer
method whose only guard was a docstring ("Not exposed through HTTP" — true,
and irrelevant). Every adapter shares the process, so:

```python
get_pairing_store().force_pair_owner("telegram", "attacker-id", user_handle="me")
```

But gating that method alone would have been **theatre**, because
`pairings.sqlite` has the same OS-layer writability as the audit db and
`lookup()` trusted whatever `trust_level` it found:

```python
sqlite3.connect("pairings.sqlite").execute(
    "INSERT OR REPLACE INTO pairings VALUES ('telegram','attacker','me','owner_paired',...)")
```

Same escalation, method untouched. **Both** doors are closed here.

**The fix.**

1. **The method needs the installer's capability.** `force_pair_owner()` now
   requires the install token. After B4 the gateway keeps only
   `sha256(token)`, so in-process code cannot produce one. Grants **and**
   refusals are audited into B2's tamper-evident log, so escalation is never
   silent. Installer/setup scripts running in their *own* process pass it
   explicitly or via `GLC_INSTALL_TOKEN` — a fallback that is safe inside the
   gateway, since `seal_install_token()` scrubs that variable at boot and any
   value still has to verify against the stored hash.
2. **Rows are signed, and unsigned rows are inert.** Every pairing carries an
   HMAC over its contents — *including `trust_level`*, so a row cannot be
   edited from `user_paired` up to `owner_paired`. `lookup()`, `owners()` and
   `all_pairings()` **refuse** rows that do not verify, so a row inserted
   straight into SQLite isn't merely detected — it does not work.
   `verify_pairings()` reports forged rows (mirroring B2's `verify_chain()`).
3. `_migrate_unsigned_rows()` signs an existing installation's rows **once**
   (guarded by `pairing_meta`), so upgrading doesn't lock the owner out —
   and, because it runs only once, a row an attacker inserts *after* the
   migration is never legitimised by a later restart.

**The key.** `config.pairing_signing_key()` is derived from the install
token's **plaintext** and held only in memory — deliberately *not* from
anything on disk. Deriving it from the stored `sha256` would be pointless:
that hash sits in `install_token`, so in-process code could re-derive the key
and forge at will. With no plaintext (local dev, legacy install) there is no
key and the store runs in **unsigned mode** — signing is neither written nor
enforced. That is why a real deployment should supply `GLC_INSTALL_TOKEN`.

**Verified.** `tests/test_b3_pairing_escalation.py` (11 tests) drives both
exploits: the method call is refused without/with a wrong token and audited;
a directly-inserted `owner_paired` row is present in SQLite yet **inert**
(`lookup` → None, `owners` → empty) and reported by `verify_pairings()`;
editing a real pairing invalidates its signature. Plus the honest path (the
installer succeeds, code-confirmed pairings sign and verify) and unsigned
mode. Full suite 330 passed.

**Honest scope.** Same ceiling as B2: the key lives in this process's memory,
so code that goes looking can read it and forge a signature. What is closed
is both named exploits; what remains needs the pairing store in its own
process — exactly the component separation the notes prescribe for leak 3.

---

## B8 — Unrestricted subprocess / shell access (leak 7)

**Invariant restored:** 8 (every run bounded in time) and least-privilege for
the gateway's own shell-outs.
**Attacker role:** 3–4 — any code sharing the gateway process.

**The bug.** The gateway shells out (the `whisper_cpp` STT slot, the system
TTS fallback), and the shipped calls had four concrete problems — none of
which is "there is a shell", which is why *removing* the shell was never the
answer:

* **PATH hijacking.** `shutil.which("whisper-cli")` and a bare `["say", …]`
  both resolve through `PATH`. In-process code can prepend a directory it
  controls and drop its own binary there, so an innocent transcription
  request executes the attacker's program. `which()` is a code-execution
  primitive.
* **No timeout.** A wedged or hostile binary blocks forever — a free denial
  of service (invariant 8).
* **Full environment inheritance.** The child received the gateway's entire
  `os.environ`.
* **Argument injection.** `say -o out <text>` passed **user text** as a bare
  argv element; `argv` is flat, so text beginning with `-` is parsed by `say`
  as an option, not speech.

**The fix.** `glc/security/exec_guard.py` is the single sanctioned way to
spawn a process. It refuses `shell=True` outright; requires `argv[0]` to be an
**absolute path inside a trusted binary directory** (`resolve_binary()` still
finds via `PATH` but then *checks where it landed*, so a planted copy is
rejected — the PATH-hijack defence); makes a **timeout mandatory**; hands the
child `minimal_env()` (a `PATH` rebuilt from the trusted dirs plus a short
allowlist — never the gateway's environment); and **audits every exec** into
B2's tamper-evident log, so a shell-out is never invisible. The allowlist is a
module constant, not an env var — an env knob would just hand an in-process
attacker the allowlist.

Call sites: `whisper_cpp/wrapper.py` resolves through the guard and is bounded
(`GLC_WHISPER_TIMEOUT_S`, default 300s). `system_fallback/adapter.py` now
passes the text **in a file** (`say -f`) instead of argv — user data never
reaches a command line at all, which beats trying to sanitise it. The telegram
dev bridge's runtime `pip install websockets` is gone: it spawned an unguarded
subprocess *and* pulled an unpinned dependency into a live process, the very
drift A5 pinned the lockfile to prevent.

**Verified.** `tests/test_b8_exec_guard.py` (14 tests): `shell=True` refused;
a **simulated PATH hijack** (a planted `whisper-cli` in a temp dir prepended
to `PATH`) is refused; relative and untrusted-absolute `argv[0]` refused;
timeout mandatory and a wedged binary really is killed; `minimal_env()`
excludes the gateway's secrets and an actual child process confirms it cannot
read `GEMINI_API_KEY`; argument injection rejected; the happy path executes
and is audited. Full suite 344 passed.

**Honest scope.** The notes say it plainly: *"removing the shell alone is
never the whole answer."* Python code can still `import subprocess` and
bypass this module entirely, or open sockets itself — nothing in-process can
prevent that. What is closed is the PATH hijack, the unbounded run, the
environment leak and the argument injection **on the gateway's own
shell-outs**, plus making the sanctioned ones auditable. The real fix is the
notes' list — per-component minimal images, sandbox isolation, non-root,
read-only filesystems, syscall filtering, egress limits — i.e. component
separation again. (`gemini_live/smoke.py` still calls `subprocess` directly;
it is a standalone manual smoke script, not imported by the gateway.)

---

## B5 — Policy engine open to monkey-patching (leak 5)

**Invariant restored:** 3/6 — *partially, and honestly.* Read the scope below
before crediting this one.
**Attacker role:** 3 (an adapter — already gone, see below) and 4 (code
executing inside the gateway — not defensible in-process).

**The bug.** Python lets any module-level function be rebound at runtime, so
one line makes policy stop mattering:

```python
glc.policy.engine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
```

**Three things that are true, and change what "fixed" can mean here:**

1. **There is no enforcement caller yet.** Nothing in `glc/routes/` calls
   `evaluate()` — the S11 agent runtime is a stub that echoes. The policy
   engine is scaffolding for a later session, so today the monkey-patch
   bypasses a check nobody is making. This fix exists so the check is guarded
   from the moment it *is* wired in.
2. **The named attacker is already gone.** Leak 5's attacker is "an adapter",
   and **A3** moved channel adapters out of this process into per-adapter
   Modal Sandboxes. An adapter has no handle on `glc.policy.engine` any more —
   no shared memory, no shared module table.
3. **Against code inside the gateway, nothing in-process helps — and neither
   does the capstone fix.** The notes prescribe running the policy engine in a
   separate process, but the **enforcement point still lives in the gateway**:
   an attacker executing there can rebind the guard, or simply never call
   policy and dispatch the tool directly. Moving the engine out protects it
   *from adapters* (which A3 already achieved), not from the gateway.

**The fix.** `glc/policy/guard.py` is the sanctioned entry point:

* it captures the real function objects **at import**, before adapter or
  dependency code runs, and calls *those* — so a rebound
  `glc.policy.engine.evaluate` is never used even when present (the exploit
  hijacks a name *lookup*; the guard does not do one);
* it verifies the engine's identity on every call (`verify_policy_integrity()`,
  mirroring B2's `verify_chain()` and B3's `verify_pairings()`);
* it **fails closed** — a process whose policy engine has been rewritten is not
  one whose verdicts mean anything, so it denies rather than trusting even the
  original engine's answer;
* it **audits** the tampering into B2's tamper-evident log.

`glc/policy/__init__.py` now exports the guarded `evaluate`, so the future
enforcement points get this by default via `from glc.policy import evaluate`;
`glc.policy.engine.evaluate` stays importable as the raw function.

**Verified.** `tests/test_b5_policy_guard.py` (11 tests) runs the notes'
exploit verbatim: the rebound lambda says "allow" and the guard still returns
**deny**, never "pirate"; rebinding the module function, the `PolicyEngine`
method, or `get_engine` is each detected; tampering fails closed even where
policy *would* have allowed (owner_paired + an unmatched tool); the tampering
is audited; integrity recovers when the patch is undone; and the package
exports the guarded entry point. Full suite 355 passed.

**Honest scope.** This is a **mitigation, not a close**. The named one-liner
no longer silently succeeds — it fails, loudly. A determined attacker with
code in the gateway rebinds `glc.policy.guard.evaluate` instead, or skips
policy altogether. That is the ceiling for B5, and unlike B2/B3 the notes'
capstone (a separate policy process) does not raise it, because the thing that
*acts* on the verdict is the gateway itself. The real boundary is keeping
untrusted code out of the gateway process — which is what A3 does for
adapters, and what invariant 3's deterministic authorisation boundary is for.

---

## B6 — An adapter that kills the gateway (leak 8)

**Invariant restored:** 8 (availability) — *for the named attacker*; 7
(nothing consequential goes unrecorded) for the rest.
**Attacker role:** 3 (an adapter — closed by A3) and 4 (code inside the
gateway — not preventable in-process).

**The bug.** Adapters shared the gateway's process, so one line ended it:

```python
os.kill(os.getpid(), signal.SIGTERM)
```

**The notes' prescribed fix is already delivered — by A3.** Leak 8's fix is,
verbatim, *"puts adapters in a separate PID namespace so they cannot see the
gateway's process."* That is exactly what A3 did: channel adapters run in
per-adapter Modal Sandboxes, each with its own PID namespace, so an adapter
that kills its own PID kills **its sandbox**, and the gateway does not notice.
The named attacker for B6 no longer shares a process with the target.

**What is left, and what this fix adds.** The remaining actor is code inside
the *gateway* — and no in-process code can stop a process from ending itself.
`os._exit()` and `SIGKILL` cannot even be intercepted. So B6's in-branch work
is **visibility**, not prevention:

* `glc/main.py` brackets the process's life with `gateway_startup` /
  `gateway_shutdown` audit events (the latter carrying uptime), written in the
  lifespan's `finally`. A SIGTERM — including the one an in-process
  `os.kill()` sends — runs uvicorn's graceful shutdown, so the kill leaves a
  trace in B2's hash chain instead of the gateway simply vanishing. The
  restart Modal performs then shows up as the next `gateway_startup`, so a
  kill/restart cycle is legible after the fact.
* `glc/routes/control.py` audits the control-plane kill, which previously left
  **no trace at all** — the single most consequential thing the control plane
  can do was unrecorded. `control_kill_accepted` is written *before* dying
  (afterwards there is no process left to write anything), and a refused
  remote kill is recorded as `control_kill_denied`, since a rejected kill is
  an attack signal worth keeping.

The remote kill remains loopback-only (the notes already call this out as
correct), and B4 still gates the endpoint behind the install token.

**Verified.** `tests/test_b6_kill_visibility.py` (7 tests): startup and
shutdown are audited and the shutdown record carries uptime and pid; a remote
kill is denied *and* audited; a kill without a token is rejected (401); and
the A3 claim is pinned — adapter work is dispatched into a Sandbox rather than
called inline, and `modal_app.py` really does set `GLC_ADAPTER_SANDBOX=1`, the
switch that puts adapters behind the PID-namespace wall on the deployment.
Full suite 362 passed.

**Honest scope.** Prevention against in-gateway code is not achievable here
and this fix does not claim it: `os._exit()` or `SIGKILL` leaves no shutdown
record, because nothing gets to run. Availability against code executing in
the gateway is a containment problem, not a coding one — Modal restarts the
container, so the blast radius is a brief outage rather than a dead install.
For the attacker the finding actually names — an adapter — A3's PID namespace
is the fix, and it is already in place.

---

## C1 — SSRF via `/v1/vision`

**Invariant restored:** 2 — *every action checked against the actual user*.
This is the **confused deputy**: the gateway applied its own identity and
network position to a request the caller chose.
**Attacker role:** 2 — a normal channel user who controls only the text they
type (plus the install token A1 now requires). **Severity: high.**

**The bug.** `_resolve_image_urls` fetched **any** `http(s)` URL the caller
supplied, with `follow_redirects=True`, no allowlist, and no size cap. The
request leaves with the gateway's credentials and from inside the gateway's
network, so the caller reaches addresses they never could themselves — a cloud
metadata service above all, which hands credentials to anything inside the
network. The bytes then come back **base64'd into the model's context**, and
per the notes' Section-12 chain, out again through the reply — an allowed
channel no egress rule blocks.

**The fix.** `glc/security/ssrf.py`, applied in `_resolve_image_urls`:

* **Check the address, not the string.** `http://2852039166/`,
  `http://0x7f000001/` and `http://[::ffff:169.254.169.254]/` are all ways of
  spelling an internal address, and a hostname can simply resolve to one. The
  host is resolved with `getaddrinfo()` and **every** returned IP is checked —
  which defeats every encoding at once, because they all resolve to the same
  number.
* **Block loopback / private / link-local / reserved / multicast / unspecified
  for IPv4 *and* IPv6**, unwrapping IPv4-mapped IPv6 so
  `::ffff:169.254.169.254` cannot smuggle a v4 address past a v6 check.
* **Re-check every redirect hop.** `follow_redirects=False`; redirects are
  followed manually and re-validated. A public URL that 302s to
  `169.254.169.254` was the whole point of the automatic redirect following.
* **Refuse non-http(s) schemes and URLs carrying credentials**, bound the
  response (16 MiB) and the chain (5 hops), and **audit** every block as
  `ssrf_blocked` — a blocked fetch is someone trying to use the gateway as a
  proxy into its own network.
* An optional `GLC_IMAGE_URL_ALLOWLIST` narrows the reachable hosts further;
  it can only ever narrow, never widen — an allowlisted internal address is
  still refused.

**Verified.** `tests/test_c1_ssrf.py` (28 tests, network-free — literal IPs
resolve locally, redirect chains use `httpx.MockTransport`): metadata,
loopback, all three RFC1918 ranges, IPv6 loopback/link-local/ULA, the
IPv4-mapped form and the decimal encoding are each refused; non-http schemes
and credential URLs refused; a **redirect from a public URL to metadata** and
to loopback are refused and redirect chains bounded; oversized bodies and a
**lying `content-length`** are both capped; the honest path still fetches; and
end-to-end `POST /v1/vision` at the metadata service returns 400 and is
audited.

**⚠ Bug found while testing this: `/v1/vision` was dead.** A1 added
`require_install_token(authorization)` to `chat()`, but `vision()` calls
`await chat(inner, request)` **without forwarding `authorization`** — so
`chat()` received FastAPI's `Header(default=None)` *sentinel object* instead
of a string and raised `AttributeError` on `.startswith`. **Every** `/v1/vision`
request had 500'd since A1. It failed *closed*, so it was never an auth
bypass, but the endpoint was unusable — and C1's SSRF was consequently
unreachable to test. Fixed by forwarding the header (`glc/routes/chat.py`),
which is why the end-to-end tests above can exist at all.

**Honest scope.** This is DNS-rebinding-**resistant**, not
rebinding-**proof**: the name is resolved and checked, then httpx resolves it
again to connect, so a record that flips between the two could in principle
slip through (a TOCTOU). Closing that needs the connection pinned to the
validated IP. What is implemented is exactly the notes' prescribed fix —
"resolve the host, block loopback, private, and link-local addresses for IPv4
and IPv6, and re-check after every redirect" — plus the allowlist, bounds and
auditing.

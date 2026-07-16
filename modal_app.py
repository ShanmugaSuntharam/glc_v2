"""
Modal deployment wrapper for glc_v1  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# Finding A5 (non-reproducible image): build from pinned inputs, not rolling
# ones, so every build is byte-reproducible and cannot drift under us.
#
#  * BASE_IMAGE is the official python:3.11-slim-bookworm pinned to an
#    immutable content digest, replacing the rolling `debian_slim`. Refresh
#    the digest when deliberately bumping the base, e.g.:
#      TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull" | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
#      curl -sI -H "Authorization: Bearer $TOKEN" \
#        -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
#        https://registry-1.docker.io/v2/library/python/manifests/3.11-slim-bookworm \
#        | grep -i docker-content-digest
#
#  * REQUIREMENTS_LOCK is the fully pinned, hash-verified export of uv.lock
#    (exact == versions for the whole transitive closure), replacing the
#    ">=" ranges that were re-resolved on every build. Regenerate after any
#    dependency change with:
#      uv export --frozen --no-dev --no-emit-project --format requirements-txt \
#        -o requirements.lock.txt
BASE_IMAGE = "python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba"
REQUIREMENTS_LOCK = Path(__file__).parent / "requirements.lock.txt"


# build_image is a function, not a plain module-level Image, because of
# finding A3: glc.sandbox.dispatch calls it again for every per-adapter
# Sandbox it creates. add_local_dir's mount was found (during live
# verification) to not reliably carry over when a Function's already-hydrated
# Image object is reused to create a brand new Sandbox - "import glc" failed
# inside the sandbox even though the same object worked fine for the Function
# itself. Rebuilding the Image fresh for each Sandbox.create() call (exactly
# like building it fresh here for the Function) avoids that entirely -- and
# with A5's pinned inputs each of those rebuilds is identical.
def build_image() -> modal.Image:
    return (
        modal.Image.from_registry(BASE_IMAGE)
        .pip_install_from_requirements(str(REQUIREMENTS_LOCK))
        # GLC_ADAPTER_SANDBOX=1: Session 12, finding A3. glc/routes/channels.py
        # runs channel-adapter code in its own Modal Sandbox (see
        # glc/sandbox/dispatch.py) instead of in-process, with network egress
        # restricted per glc/channels.yaml. Off by default (unset -> in-process,
        # what local dev and the test suite use) so this is opt-in per-deployment.
        .env({"GLC_CONFIG_DIR": "/data/glc", "GLC_ADAPTER_SANDBOX": "1"})
        # Bake the lockfile into the image at the SAME path build_image()
        # resolves (Path(__file__).parent is /root inside the container). A3
        # calls build_image() again from *inside* the running gateway to make
        # each per-adapter Sandbox, and pip_install_from_requirements must be
        # able to read the lockfile there too -- otherwise the runtime Sandbox
        # build fails with FileNotFoundError. Mirrors how glc/ is carried in.
        .add_local_file(str(REQUIREMENTS_LOCK), remote_path="/root/requirements.lock.txt")
        .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
    )


image = build_image()

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Finding A4 (leak 1): ONE Secret per provider, not one shared "glc-llm-keys"
# holding all of them. Each is delivered to the gateway at startup, and then
# glc.security.keyvault.seal() (called in glc.main's lifespan) snapshots every
# key into a private in-process store and DELETES it from os.environ, so no
# in-process code can read a provider key via os.getenv() / /proc/self/environ.
# Splitting the Secret removes the single-Secret shape and lets each key be
# scoped and rotated on its own (and is the groundwork for the per-call
# Sandbox isolation, Moves 2-4 / option A — see docs/SECURITY_FIXES.md).
#
# Create them once (mock values only) with:
#   uv run modal secret create glc-provider-gemini     GEMINI_API_KEY=mock-not-real
#   uv run modal secret create glc-provider-nvidia     NVIDIA_API_KEY=mock-not-real
#   uv run modal secret create glc-provider-groq       GROQ_API_KEY=mock-not-real
#   uv run modal secret create glc-provider-cerebras   CEREBRAS_API_KEY=mock-not-real
#   uv run modal secret create glc-provider-openrouter OPEN_ROUTER_API_KEY=mock-not-real
#   uv run modal secret create glc-provider-github     GITHUB_ACCESS_TOKEN=mock-not-real
PROVIDER_SECRET_NAMES = [
    "glc-provider-gemini",
    "glc-provider-nvidia",
    "glc-provider-groq",
    "glc-provider-cerebras",
    "glc-provider-openrouter",
    "glc-provider-github",
]
llm_secrets = [modal.Secret.from_name(n) for n in PROVIDER_SECRET_NAMES]

# Finding B4 (leak 4): the install token used to sit on the Volume in
# plaintext, so any in-process code could read it and act as the operator. The
# gateway now keeps only sha256(token) and verifies against that, so there is
# nothing recoverable on disk. Supplying the token here means YOU choose it and
# already know it -- the gateway never has to hand it back:
#   uv run modal secret create glc-install-token GLC_INSTALL_TOKEN=<pick-a-strong-value>
# glc.config.seal_install_token() scrubs it from os.environ at boot (same move
# as A4), so in-process code cannot os.getenv() it either.
install_token_secret = modal.Secret.from_name("glc-install-token")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[*llm_secrets, install_token_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
    # Finding A6: the audit / pairing / cost databases are SQLite files on the
    # shared Volume. SQLite is a single-writer store and a Modal Volume is not
    # a concurrent-write filesystem, so if autoscale ran two containers they
    # would corrupt or split the audit trail (invariant 7). Cap the gateway at
    # one container: with min=0/max=1 there are only ever 0 or 1 writers, never
    # two. (Correctness of the audit log over horizontal scale is the right
    # trade for a gateway; a real multi-writer DB is the alternative.)
    max_containers=1,
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    # Finding A6: a write to a Modal Volume mount is not durable until the
    # Volume is committed. Register data_volume.commit as the audit store's
    # per-append flush so the trail survives container shutdown / scale-to-zero.
    # (reload() is unnecessary here: max_containers=1 means no other writer can
    # advance the Volume behind this container's back.)
    from glc.audit import store as audit_store

    audit_store.set_commit_hook(data_volume.commit)

    # Finding A3: let glc.sandbox.dispatch spin up per-adapter Sandboxes
    # against this same App, rebuilding the Image fresh each time (see
    # build_image's docstring comment above for why).
    from glc.sandbox import dispatch

    dispatch.configure(app=app, image_builder=build_image)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    return web

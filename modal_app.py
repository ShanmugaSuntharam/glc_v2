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

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
#
# This is a function, not a plain module-level Image, because of finding
# A3: glc.sandbox.dispatch calls it again for every per-adapter Sandbox it
# creates. add_local_dir's mount was found (during live verification) to
# not reliably carry over when a Function's already-hydrated Image object
# is reused to create a brand new Sandbox - "import glc" failed inside the
# sandbox even though the same object worked fine for the Function itself.
# Rebuilding the Image fresh for each Sandbox.create() call (exactly like
# building it fresh here for the Function) avoids that entirely.
def build_image() -> modal.Image:
    return (
        modal.Image.debian_slim(python_version="3.11")
        .pip_install(
            "fastapi>=0.110",
            "uvicorn[standard]>=0.27",
            "httpx>=0.27",
            "python-dotenv>=1.0",
            "pydantic>=2.6",
            "jsonschema>=4.21",
            "pyyaml>=6.0",
            "websockets>=12.0",
            "twilio>=9.0",
            "modal>=1.5.1",
        )
        # GLC_ADAPTER_SANDBOX=1: Session 12, finding A3. glc/routes/channels.py
        # runs channel-adapter code in its own Modal Sandbox (see
        # glc/sandbox/dispatch.py) instead of in-process, with network egress
        # restricted per glc/channels.yaml. Off by default (unset -> in-process,
        # what local dev and the test suite use) so this is opt-in per-deployment.
        .env({"GLC_CONFIG_DIR": "/data/glc", "GLC_ADAPTER_SANDBOX": "1"})
        .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
    )


image = build_image()

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    # Finding A3: let glc.sandbox.dispatch spin up per-adapter Sandboxes
    # against this same App, rebuilding the Image fresh each time (see
    # build_image's docstring comment above for why).
    from glc.sandbox import dispatch

    dispatch.configure(app=app, image_builder=build_image)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    return web

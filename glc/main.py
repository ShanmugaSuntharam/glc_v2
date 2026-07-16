"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import seal_install_token  # noqa: E402
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402
from glc.security import keyvault  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))


def _audit_lifecycle(event_type: str, params: dict) -> None:
    """Finding B6: record the gateway starting and stopping.

    An in-process `os.kill(os.getpid(), SIGTERM)` cannot be prevented from
    inside the process, but it does not have to be *silent*. A shutdown event
    (and the startup that follows Modal restarting the container) lands in the
    audit log, so a kill leaves a trace in B2's hash chain instead of the
    gateway simply vanishing. Never let auditing break start/stop.
    """
    try:
        from glc.audit import append as audit_append

        audit_append(
            channel="_system",
            channel_user_id="_gateway",
            trust_level="owner_paired",
            event_type=event_type,
            params=params,
        )
    except Exception:
        pass


def _install_sighup_reload() -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    def _handler(signum, frame):  # noqa: ARG001
        try:
            reload_engine()
            print("[glc] policy.yaml reloaded via SIGHUP")
        except Exception as e:
            print(f"[glc] SIGHUP reload failed: {e!r}")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    init_audit()
    # Finding B4: resolve the install token once, keep only its sha256, and
    # drop every recoverable copy (GLC_INSTALL_TOKEN scrubbed from the
    # environment, any legacy on-disk plaintext hashed in place). A freshly
    # generated token is returned exactly once -- the only chance to show it.
    _fresh_token = seal_install_token()
    if _fresh_token:
        print(
            "[glc] new install token (shown once, store it now — "
            f"it cannot be recovered): {_fresh_token}"
        )
    _install_sighup_reload()
    # Finding A4 (leak 1): pull every provider key out of os.environ into the
    # private keyvault before anything builds providers, so no in-process code
    # can read a provider credential via os.getenv() or /proc/self/environ.
    keyvault.seal()
    app.state.cache = GeminiCache(ttl_seconds=300)
    app.state.providers = P.build_providers(app.state.cache)
    app.state.router = Router(app.state.providers, chat_route.ORDER)
    app.state.router_providers = P.build_router_providers()
    app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
    app.state.embedders, app.state.embed_order = E.build_embedders()
    app.state.started_at = time.time()
    app.state.registered_channels = []
    # Finding B6: bracket the process's life with audit events, so a kill (and
    # the restart that follows it) is visible in the log rather than the
    # gateway just disappearing.
    _audit_lifecycle("gateway_startup", {"pid": os.getpid()})
    try:
        yield
    finally:
        _audit_lifecycle(
            "gateway_shutdown",
            {"pid": os.getpid(), "uptime_s": int(time.time() - app.state.started_at)},
        )


# Finding A2: /docs, /redoc, and /openapi.json publicly leaked the full
# route map with no auth. Off by default; set GLC_ENABLE_DOCS=1 to opt in
# (e.g. for local development).
_DOCS_ENABLED = os.getenv("GLC_ENABLE_DOCS") == "1"

app = FastAPI(
    title="GLC v1 — Gateway for LLMs and Channels",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

app.include_router(chat_route.router)
app.include_router(transcribe_route.router)
app.include_router(speak_route.router)
app.include_router(control_route.router)
app.include_router(channels_route.router)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    docs_line = (
        "<p>Open <code>/docs</code> for the OpenAPI explorer.</p>"
        if _DOCS_ENABLED
        else "<p>The OpenAPI explorer is disabled on this deployment "
        "(set <code>GLC_ENABLE_DOCS=1</code> to enable it).</p>"
    )
    return (
        "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
        "<h1>GLC v1</h1>"
        "<p>Gateway for LLMs and Channels — Session 11 scaffold.</p>"
        f"{docs_line}"
        "<p>Channel adapters connect over <code>WS /v1/channels/&lt;name&gt;</code>."
        " V9 callers should point at this port unchanged: chat, vision, embed,"
        " batch, cost-by-agent, providers, capabilities, status, calls."
        "</p>"
        "</body></html>"
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "port": PORT}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)

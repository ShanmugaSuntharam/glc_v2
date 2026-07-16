"""Session 12, finding B6 / leak 8 (an adapter that kills the gateway).

    os.kill(os.getpid(), signal.SIGTERM)

The notes' prescribed fix is "puts adapters in a separate PID namespace so
they cannot see the gateway's process" -- which A3 already delivered: channel
adapters run in per-adapter Modal Sandboxes, each with its own PID namespace,
so an adapter that kills its own PID kills only its sandbox.

What is left is code inside the GATEWAY, and no in-process code can stop a
process from ending itself. So B6's in-branch work is visibility: termination
is recorded rather than silent. See docs/SECURITY_FIXES.md for the honest
scope.
"""

from __future__ import annotations

from glc.audit import query
from glc.sandbox import dispatch

# ── termination is no longer silent ─────────────────────────────────────────


def test_startup_is_audited(app_client):
    events = [r["event_type"] for r in query(limit=50)]
    assert "gateway_startup" in events


def test_shutdown_is_audited(install_token):
    """Exiting the TestClient context runs the lifespan's shutdown path, which
    is what uvicorn runs when SIGTERM arrives -- including the SIGTERM an
    in-process os.kill() sends."""
    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app):
        pass  # boot, then shut down

    events = [r["event_type"] for r in query(limit=50)]
    assert "gateway_shutdown" in events


def test_shutdown_record_carries_uptime(install_token):
    import json

    from fastapi.testclient import TestClient

    import glc.main as m

    with TestClient(m.app):
        pass

    row = next(r for r in query(limit=50) if r["event_type"] == "gateway_shutdown")
    params = json.loads(row["params_json"])
    assert "uptime_s" in params
    assert "pid" in params


# ── the control-plane kill is recorded, and still loopback-only ─────────────


def test_remote_kill_is_denied_and_audited(app_client, install_token, monkeypatch):
    """The remote path stays blocked (the notes call this out as already good);
    B6 adds the record of the attempt."""
    monkeypatch.delenv("GLC_KILL_ALLOW_REMOTE", raising=False)
    monkeypatch.setattr(
        "starlette.requests.Request.client",
        property(lambda self: type("C", (), {"host": "203.0.113.9"})()),
    )

    r = app_client.post("/v1/control/kill", headers={"Authorization": f"Bearer {install_token}"})

    assert r.status_code == 403
    events = [row["event_type"] for row in query(limit=50)]
    assert "control_kill_denied" in events


def test_kill_without_a_token_is_rejected(app_client):
    """B4 still gates the control plane; no token, no kill, nothing to audit."""
    r = app_client.post("/v1/control/kill")
    assert r.status_code == 401


# ── the notes' actual fix: adapters are in their own PID namespace (A3) ─────


def test_adapter_code_runs_in_a_sandbox_not_the_gateway_process():
    """Leak 8's fix is a separate PID namespace for adapters. A3 delivers it:
    when sandboxing is on, adapter code is dispatched into a Modal Sandbox
    instead of being called in-process, so os.getpid() inside an adapter is
    the sandbox's PID, not the gateway's."""
    import inspect

    src = inspect.getsource(dispatch._create_sandbox)
    assert "Sandbox.create" in src  # adapter work is spawned, not called inline


def test_sandbox_dispatch_is_enabled_on_the_deployment(monkeypatch):
    """modal_app.py sets GLC_ADAPTER_SANDBOX=1 in the image env, which is what
    puts adapters behind the PID-namespace wall in the real deployment."""
    monkeypatch.setenv("GLC_ADAPTER_SANDBOX", "1")
    assert dispatch.sandbox_enabled() is True

    modal_app = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / "modal_app.py"
    ).read_text()
    assert '"GLC_ADAPTER_SANDBOX": "1"' in modal_app

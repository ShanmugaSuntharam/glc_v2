"""Gateway-side orchestration for Session 12, finding A3.

Only active when GLC_ADAPTER_SANDBOX=1 (set in modal_app.py's image env,
so this is a no-op for local dev via daemon/ and for the test suite).
glc/routes/channels.py calls into this module instead of instantiating
and calling channel-adapter code directly, so untrusted adapter code
runs in its own Modal Sandbox with a per-channel network egress policy
(glc/channels.yaml's outbound_domains / block_network) instead of
sharing the gateway's process and unrestricted network.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.config import load_channels

RUNNER_TIMEOUT_S = 25

# Channels with a real credential today (see the finding A3 design doc /
# commit message): each gets its own scoped Modal Secret, glc-adapter-<name>,
# mock values only. Channels not in this set get no secret at all.
ADAPTER_SECRETS = frozenset(
    {"telegram", "whatsapp", "gmail", "twilio_sms", "teams", "webhook", "twilio_voice"}
)

_state: dict[str, Any] = {"app": None, "image": None}


class SandboxAdapterError(RuntimeError):
    """adapter_runner.py reported an error from inside the sandbox."""


def configure(app: Any, image: Any) -> None:
    """Called once by modal_app.py at boot so Sandboxes reuse the
    gateway's own App/Image - no duplicate image build, no lookup-by-name
    race against a not-yet-deployed app."""
    _state["app"] = app
    _state["image"] = image


def sandbox_enabled() -> bool:
    return os.getenv("GLC_ADAPTER_SANDBOX") == "1"


def network_policy_for(channel: str) -> dict[str, Any]:
    cfg = load_channels()
    defaults = cfg.get("defaults", {})
    entry = cfg.get("channels", {}).get(channel, {})
    return {
        "block_network": bool(entry.get("block_network", defaults.get("block_network", False))),
        "outbound_domains": entry.get("outbound_domains", defaults.get("outbound_domains", [])),
    }


@dataclass
class SandboxSession:
    sandbox: Any  # modal.Sandbox - left untyped so importing this module never requires `modal`


async def _create_sandbox(name: str) -> Any:
    import modal

    if _state["app"] is None:
        raise RuntimeError("glc.sandbox.dispatch.configure() was never called - not running under Modal")

    policy = network_policy_for(name)
    secrets = [modal.Secret.from_name(f"glc-adapter-{name}")] if name in ADAPTER_SECRETS else []
    kwargs: dict[str, Any] = {
        "app": _state["app"],
        "image": _state["image"],
        "secrets": secrets,
        "timeout": RUNNER_TIMEOUT_S,
    }
    if policy["block_network"]:
        kwargs["block_network"] = True
    else:
        kwargs["outbound_domain_allowlist"] = policy["outbound_domains"]
    return await modal.Sandbox.create.aio(**kwargs)


async def _exec(sandbox: Any, mode: str, name: str, payload: dict) -> dict:
    # Payload travels as a base64 argv, not over stdin: calling
    # stdin.write_eof() on a Sandbox.exec process was observed (during
    # live verification of this finding) to tear down the whole sandbox
    # container, not just close that one exec's stdin - so stdin is never
    # used here. /root is already on sys.path by default in this image
    # (confirmed empirically), so "import glc" resolves without needing
    # an explicit workdir either.
    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    proc = await sandbox.exec.aio("python", "-m", "glc.sandbox.adapter_runner", mode, name, payload_b64)
    out = await proc.stdout.read.aio()
    await proc.wait.aio()
    if not out:
        err = await proc.stderr.read.aio()
        return {"error": f"adapter_runner produced no output (exit {proc.returncode}): {err}"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"error": f"adapter_runner produced invalid JSON: {out!r}"}


async def on_message_via_sandbox(name: str, raw: dict) -> tuple[ChannelMessage | None, SandboxSession]:
    sandbox = await _create_sandbox(name)
    session = SandboxSession(sandbox=sandbox)
    payload = {
        "raw_body_b64": base64.b64encode(raw["raw_body"]).decode(),
        "headers": raw["headers"],
    }
    result = await _exec(sandbox, "on_message", name, payload)
    if "error" in result:
        await close_sandbox(session)
        raise SandboxAdapterError(result["error"])
    if result["result"] is None:
        return None, session
    return ChannelMessage.model_validate(result["result"]), session


async def send_via_sandbox(session: SandboxSession, name: str, reply: ChannelReply) -> Any:
    try:
        payload = {"reply": json.loads(reply.model_dump_json())}
        result = await _exec(session.sandbox, "send", name, payload)
        if "error" in result:
            raise SandboxAdapterError(result["error"])
        return result["result"]
    finally:
        await close_sandbox(session)


async def close_sandbox(session: SandboxSession) -> None:
    try:
        await session.sandbox.terminate.aio()
    except Exception:
        pass

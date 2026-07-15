"""In-sandbox entrypoint (Session 12, finding A3).

This module is the only code that runs *inside* a channel's Modal
Sandbox, network-restricted to that channel's outbound_domains. It never
touches the gateway's audit/pairing databases, install token, or the
LLM provider Secret — it only imports glc.channels.registry (unchanged)
to instantiate the one named adapter and calls on_message/send on it.

Usage (invoked by glc.sandbox.dispatch via Sandbox.exec):
    python -m glc.sandbox.adapter_runner <on_message|send> <channel_name>
    stdin:  one JSON object (see _run_on_message/_run_send for shape)
    stdout: one JSON object: {"result": ...} or {"error": "..."}
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys

from glc.channels import registry
from glc.channels.envelope import ChannelReply


def _json_safe(value: object) -> object:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _run_on_message(name: str, payload: dict) -> dict:
    adapter = registry.instantiate(name)
    raw = {
        "raw_body": base64.b64decode(payload["raw_body_b64"]),
        "headers": payload["headers"],
    }
    msg = asyncio.run(adapter.on_message(raw))
    if msg is None:
        return {"result": None}
    return {"result": json.loads(msg.model_dump_json())}


def _run_send(name: str, payload: dict) -> dict:
    adapter = registry.instantiate(name)
    reply = ChannelReply.model_validate(payload["reply"])
    result = asyncio.run(adapter.send(reply))
    return {"result": _json_safe(result)}


def dispatch(mode: str, name: str, payload: dict) -> dict:
    """mode in ("on_message", "send"). Never raises - always returns a
    JSON-safe dict, either {"result": ...} or {"error": "..."}."""
    try:
        return _run_on_message(name, payload) if mode == "on_message" else _run_send(name, payload)
    except Exception as e:  # noqa: BLE001 - must always emit valid JSON, never crash silently
        return {"error": f"{type(e).__name__}: {e}"}


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in ("on_message", "send"):
        print(
            json.dumps({"error": "usage: adapter_runner.py <on_message|send> <channel_name>"}),
            file=sys.stderr,
        )
        raise SystemExit(2)

    mode, name = sys.argv[1], sys.argv[2]
    payload = json.loads(sys.stdin.read())
    out = dispatch(mode, name, payload)
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


if __name__ == "__main__":
    main()

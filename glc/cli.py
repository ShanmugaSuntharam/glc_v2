"""glc CLI entry point. `uv run glc serve` boots the gateway."""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="glc")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="boot the gateway")
    p_serve.add_argument("--host", default=os.getenv("GLC_HOST", "0.0.0.0"))
    p_serve.add_argument("--port", type=int, default=int(os.getenv("GLC_PORT", "8111")))
    p_serve.add_argument("--reload", action="store_true")

    p_token = sub.add_parser(
        "token",
        help="show the per-installation control token (only ever shown once, at creation)",
    )
    p_token.add_argument(
        "--rotate",
        action="store_true",
        help="mint a fresh token, invalidating the old one, and print it once",
    )
    sub.add_parser("channels", help="list channels discovered in the catalogue")

    args = parser.parse_args()

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("glc.main:app", host=args.host, port=args.port, reload=args.reload)
        return 0
    if args.cmd == "token":
        # Session 12 finding B4: the gateway stores only sha256(token), so a
        # token can no longer be read back out of the installation -- by us or
        # by an attacker with code in the process. It is shown once, at
        # creation; after that the only way to get a usable token is to rotate.
        from glc.config import install_token_is_set, rotate_install_token, seal_install_token

        if args.rotate:
            print(rotate_install_token())
            return 0
        if install_token_is_set():
            print(
                "An install token is already set. It is stored as a hash and cannot be "
                "shown again.\nRun `glc token --rotate` to mint a new one (this "
                "invalidates the current token).",
                file=sys.stderr,
            )
            return 1
        fresh = seal_install_token()
        print(fresh if fresh else "", end="\n" if fresh else "")
        return 0
    if args.cmd == "channels":
        from glc.channels.registry import discover

        for name, cls in sorted(discover().items()):
            print(f"  {name:14}  {cls.__module__}.{cls.__name__}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

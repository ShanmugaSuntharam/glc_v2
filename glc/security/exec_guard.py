"""Session 12, finding B8 (leak 7) — unrestricted subprocess / shell access.

The gateway shells out (the whisper_cpp STT slot, the system TTS fallback),
and because nothing was separated, any code in the process could spawn
anything too. The shipped calls had four concrete problems:

  * PATH hijacking. `shutil.which("whisper-cli")` and bare `["say", ...]` both
    resolve through PATH, and in-process code can prepend a directory to PATH
    and drop its own binary there. A "harmless" transcription request then
    executes the attacker's program. which() is a code-execution primitive.
  * No timeout. A wedged or hostile binary blocks forever (invariant 8: every
    run needs a hard limit on time).
  * Full environment inheritance. The child got the gateway's entire
    os.environ. A4 scrubbed the provider keys, but a child process still has
    no business seeing the parent's environment.
  * Argument injection. argv is a flat list, so a binary cannot tell a value
    from a flag: user text starting with "-" is parsed as an option.

This module is the single sanctioned way to spawn a process. It refuses
shell=True outright, requires an absolute binary inside a trusted directory,
makes a timeout mandatory, hands the child a minimal environment, and audits
every exec so a shell-out is never invisible.

Honest scope: the notes say it plainly -- "removing the shell alone is never
the whole answer". A Python process can still call subprocess directly,
bypassing this module entirely, or open sockets itself. Nothing in-process can
prevent that. What this closes is the PATH hijack, the unbounded run, the
environment leak, and argument injection on the gateway's OWN shell-outs, and
it makes the sanctioned ones auditable. The real fix is the notes' list:
per-component minimal images, sandbox isolation, non-root, read-only
filesystems, syscall filtering, and egress limits -- component separation
again (see docs/SECURITY_FIXES.md).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Every sanctioned exec is bounded. Invariant 8.
DEFAULT_TIMEOUT_S = 120


class ExecNotPermitted(RuntimeError):
    """The exec guard refused to spawn this process."""


def _default_trusted_dirs() -> tuple[Path, ...]:
    """Directories a binary may legitimately live in.

    Deliberately a module constant rather than an env var: an env knob would
    simply hand an in-process attacker the allowlist, which is the very thing
    being defended.
    """
    if os.name == "nt":
        return (
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32",
            Path(sys.prefix) / "Scripts",
        )
    return (
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/bin"),
        Path("/usr/sbin"),
        Path("/sbin"),
        Path("/opt/homebrew/bin"),  # macOS dev boxes
    )


TRUSTED_BIN_DIRS: tuple[Path, ...] = _default_trusted_dirs()


def _is_trusted(exe: Path) -> bool:
    try:
        parent = exe.resolve().parent
    except OSError:
        return False
    for d in TRUSTED_BIN_DIRS:
        try:
            if parent == d.resolve():
                return True
        except OSError:
            continue
    return False


def resolve_binary(name: str) -> str:
    """Resolve `name` to an absolute path, and refuse it unless it lives in a
    trusted directory.

    This is the PATH-hijack defence: which() is still used to find the binary,
    but where it lands is then checked, so a copy planted in /tmp (or anywhere
    else an attacker can write) is rejected rather than executed.
    """
    found = shutil.which(name)
    if not found:
        raise ExecNotPermitted(f"{name!r} was not found on PATH")
    exe = Path(found).resolve()
    if not _is_trusted(exe):
        raise ExecNotPermitted(
            f"refusing to execute {exe}: not in a trusted binary directory "
            f"({', '.join(str(d) for d in TRUSTED_BIN_DIRS)}). "
            "This is what a PATH hijack looks like."
        )
    return str(exe)


def data_arg(value: str, *, name: str = "argument") -> str:
    """Assert that `value` is DATA, not a flag.

    argv is flat: a binary cannot tell "the user said -o" from "the caller
    passed the -o option". Any user-controlled value that must reach a
    command line goes through here. Prefer passing user text via a file or
    stdin instead -- then it never touches argv at all.
    """
    if value.startswith("-"):
        raise ExecNotPermitted(
            f"{name} must not begin with '-': it would be parsed as an option (argument injection)"
        )
    return value


def minimal_env() -> dict[str, str]:
    """The environment a child process gets: what it needs, nothing else.

    PATH is rebuilt from the trusted directories, so even a child that shells
    out further cannot be steered by a poisoned PATH.
    """
    env = {"PATH": os.pathsep.join(str(d) for d in TRUSTED_BIN_DIRS)}
    for key in ("HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SystemRoot", "USERPROFILE"):
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


def run(
    argv: list[str],
    *,
    timeout: float | None = DEFAULT_TIMEOUT_S,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """The only sanctioned way to spawn a process.

    Refuses shell=True, requires argv[0] to be an absolute path in a trusted
    directory (use resolve_binary()), requires a timeout, and defaults the
    child to minimal_env(). Every call is audited.
    """
    if kwargs.pop("shell", False):
        raise ExecNotPermitted("shell=True is never permitted")
    if not argv:
        raise ExecNotPermitted("empty argv")

    exe = Path(argv[0])
    if not exe.is_absolute():
        raise ExecNotPermitted(
            f"argv[0] must be an absolute path, got {argv[0]!r} — resolve it with resolve_binary()"
        )
    if not _is_trusted(exe):
        raise ExecNotPermitted(f"refusing to execute {exe}: not in a trusted binary directory")
    if timeout is None or timeout <= 0:
        raise ExecNotPermitted("a timeout is mandatory (invariant 8: bound every run)")

    kwargs.setdefault("env", minimal_env())
    _audit_exec(argv, timeout)
    return subprocess.run(argv, shell=False, timeout=timeout, **kwargs)  # noqa: S603


def _audit_exec(argv: list[str], timeout: float) -> None:
    """A shell-out is a security event; record it. Never let auditing failure
    break the caller."""
    try:
        from glc.audit import append as audit_append

        audit_append(
            channel="_system",
            channel_user_id="_gateway",
            trust_level="owner_paired",
            event_type="subprocess_exec",
            params={"binary": argv[0], "argc": len(argv), "timeout_s": timeout},
        )
    except Exception:
        pass

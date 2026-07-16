"""Session 12, finding B8 / leak 7 (unrestricted subprocess & shell access):
the gateway shells out (whisper_cpp STT, system TTS fallback) and the shipped
calls resolved binaries through PATH, ran without a timeout, inherited the
whole environment, and passed user text straight into argv.

glc.security.exec_guard is now the single sanctioned way to spawn a process.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from glc.security import exec_guard
from glc.security.exec_guard import ExecNotPermitted


@pytest.fixture
def trust_python(monkeypatch):
    """Trust the interpreter's own directory so the happy path can really exec."""
    monkeypatch.setattr(
        exec_guard, "TRUSTED_BIN_DIRS", (Path(sys.executable).resolve().parent,)
    )


# ── the shell is never available ────────────────────────────────────────────


def test_shell_true_is_refused(trust_python):
    with pytest.raises(ExecNotPermitted, match="shell=True"):
        exec_guard.run([sys.executable, "-c", "pass"], shell=True)


# ── PATH hijacking ──────────────────────────────────────────────────────────


def test_binary_outside_a_trusted_dir_is_refused(tmp_path, monkeypatch):
    """The PATH hijack: an attacker drops a binary in a directory they control
    and prepends it to PATH. which() would happily return it."""
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    evil = evil_dir / ("whisper-cli.exe" if os.name == "nt" else "whisper-cli")
    evil.write_text("#!/bin/sh\necho pwned\n")
    evil.chmod(0o755)
    monkeypatch.setenv("PATH", str(evil_dir) + os.pathsep + os.environ.get("PATH", ""))

    with pytest.raises(ExecNotPermitted, match="PATH hijack"):
        exec_guard.resolve_binary("whisper-cli")


def test_run_refuses_an_untrusted_absolute_path(tmp_path, trust_python):
    planted = tmp_path / "planted"
    planted.write_text("x")

    with pytest.raises(ExecNotPermitted, match="trusted binary directory"):
        exec_guard.run([str(planted)], timeout=5)


def test_run_refuses_a_relative_argv0(trust_python):
    with pytest.raises(ExecNotPermitted, match="absolute path"):
        exec_guard.run(["python"], timeout=5)


def test_resolve_binary_accepts_a_trusted_binary(trust_python):
    assert exec_guard.resolve_binary(Path(sys.executable).name) is not None


# ── every run is bounded (invariant 8) ──────────────────────────────────────


def test_timeout_is_mandatory(trust_python):
    with pytest.raises(ExecNotPermitted, match="timeout is mandatory"):
        exec_guard.run([sys.executable, "-c", "pass"], timeout=None)
    with pytest.raises(ExecNotPermitted, match="timeout is mandatory"):
        exec_guard.run([sys.executable, "-c", "pass"], timeout=0)


def test_a_wedged_binary_is_killed(trust_python):
    import subprocess

    with pytest.raises(subprocess.TimeoutExpired):
        exec_guard.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)


# ── the child gets a minimal environment ────────────────────────────────────


def test_minimal_env_excludes_the_gateway_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "super-secret")
    monkeypatch.setenv("GLC_INSTALL_TOKEN", "super-secret")

    env = exec_guard.minimal_env()

    assert "GEMINI_API_KEY" not in env
    assert "GLC_INSTALL_TOKEN" not in env
    assert "PATH" in env


def test_child_process_does_not_inherit_gateway_secrets(trust_python, monkeypatch):
    """End to end: the spawned process genuinely cannot see them."""
    monkeypatch.setenv("GEMINI_API_KEY", "super-secret")

    out = exec_guard.run(
        [sys.executable, "-c", "import os; print(os.getenv('GEMINI_API_KEY'))"],
        timeout=30,
        capture_output=True,
        text=True,
    )

    assert out.stdout.strip() == "None"


def test_minimal_env_path_is_rebuilt_from_trusted_dirs(trust_python):
    env = exec_guard.minimal_env()
    assert env["PATH"] == str(Path(sys.executable).resolve().parent)


# ── argument injection ──────────────────────────────────────────────────────


def test_data_arg_rejects_a_value_that_looks_like_a_flag():
    with pytest.raises(ExecNotPermitted, match="argument injection"):
        exec_guard.data_arg("-o/tmp/pwned", name="text")


def test_data_arg_passes_ordinary_text():
    assert exec_guard.data_arg("hello world") == "hello world"


# ── the happy path still works, and is audited ──────────────────────────────


def test_sanctioned_run_executes(trust_python):
    out = exec_guard.run(
        [sys.executable, "-c", "print('ok')"], timeout=30, capture_output=True, text=True
    )
    assert out.stdout.strip() == "ok"


def test_every_exec_is_audited(trust_python):
    from glc.audit import query

    exec_guard.run([sys.executable, "-c", "pass"], timeout=30, capture_output=True)

    events = [r["event_type"] for r in query(limit=10)]
    assert "subprocess_exec" in events

"""Session 12, finding A3: isolates untrusted channel-adapter code from
the trusted gateway process, running it in a Modal Sandbox with a
network egress allowlist instead of sharing the gateway's process/network.

See adapter_runner.py (runs inside the sandbox) and dispatch.py (runs in
the gateway, orchestrates the sandbox).
"""

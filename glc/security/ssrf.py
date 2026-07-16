"""Session 12, finding C1 — server-side request forgery via /v1/vision.

`_resolve_image_urls` fetched any http(s) URL the caller supplied, with
follow_redirects=True and no allowlist. The request goes out with the
GATEWAY's identity and network position, so the caller borrows both: it can
reach addresses it could never reach itself, most famously a cloud metadata
service, which hands credentials to anything inside the network. The fetched
bytes then come back base64'd into the model's context -- and, per the notes'
Section 12 chain, out again through the reply, an allowed channel that no
egress rule blocks.

The defence has to check the ADDRESS, not the string:

  * Never trust the host text. `http://2852039166/`, `http://0x7f000001/` and
    `http://[::ffff:169.254.169.254]/` are all ways of writing an internal
    address, and a hostname can simply resolve to one. So the host is resolved
    with getaddrinfo() and every resulting IP is checked -- which covers every
    encoding at once, because they all resolve to the same number.
  * Block loopback / private / link-local / reserved / multicast for BOTH IPv4
    and IPv6, and unwrap IPv4-mapped IPv6 (::ffff:169.254.169.254) so it
    cannot smuggle a v4 address past a v6 check.
  * Re-check after EVERY redirect. A public URL that 302s to
    169.254.169.254 defeats any check done only on the first URL, which is
    exactly what follow_redirects=True did automatically and invisibly.
  * Bound the response, so a "vision request" cannot pull an unbounded body
    into memory (invariant 8).

Honest scope: this is DNS-rebinding-resistant, not DNS-rebinding-proof. The
name is resolved and checked, then httpx resolves it again to connect, so a
record that flips between the two could in principle slip through (a TOCTOU).
Closing that needs the connection pinned to the validated IP. The notes'
prescribed fix -- "resolve the host, block loopback, private, and link-local
addresses for IPv4 and IPv6, and re-check after every redirect" -- is what is
implemented here.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

# A vision fetch is a network call made on the caller's behalf: bound it.
DEFAULT_TIMEOUT_S = 15
MAX_REDIRECTS = 5
MAX_IMAGE_BYTES = 16 * 1024 * 1024  # 16 MiB

# Optional host allowlist. When set (comma-separated), an image may only be
# fetched from these hosts; when unset, any PUBLIC address is allowed and only
# the internal ranges below are refused. Setting it can only ever narrow what
# is reachable, never widen it.
ALLOWLIST_ENV = "GLC_IMAGE_URL_ALLOWLIST"


class SSRFBlocked(Exception):
    """A URL was refused before any request was made."""


def _blocked_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    # ::ffff:169.254.169.254 is the metadata service wearing a v6 hat. Unwrap
    # it, or a v4 rule never sees it.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # Ordered most-specific first, purely so the error names the real reason.
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (cloud metadata lives here)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    return None


def _allowlist() -> set[str]:
    raw = os.getenv(ALLOWLIST_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def resolve_and_check(host: str, port: int) -> list[str]:
    """Resolve `host` and refuse it if ANY address it answers to is internal.

    Every address is checked, not just the first: a name that returns one
    public and one private address must not be usable to reach the private one.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFBlocked(f"cannot resolve host {host!r}: {e}") from None

    addrs: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            raise SSRFBlocked(f"unparseable address {raw!r} for host {host!r}") from None
        reason = _blocked_reason(ip)
        if reason:
            raise SSRFBlocked(
                f"refusing to fetch {host!r}: it resolves to {ip}, which is {reason}. "
                "The gateway will not make requests to internal addresses on a caller's behalf."
            )
        addrs.append(str(ip))
    if not addrs:
        raise SSRFBlocked(f"host {host!r} resolved to no addresses")
    return addrs


def validate_url(url: str) -> str:
    """Check one URL: scheme, shape, host, and every address it resolves to.
    Returns the host. Raises SSRFBlocked."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlocked(f"refusing scheme {parsed.scheme!r}: only http and https are fetchable")
    if parsed.username or parsed.password:
        # http://user:pass@host smuggles credentials and confuses host parsing.
        raise SSRFBlocked("refusing a URL that carries credentials")
    host = parsed.hostname
    if not host:
        raise SSRFBlocked(f"no host in URL {url!r}")

    allow = _allowlist()
    if allow and host.lower() not in allow:
        raise SSRFBlocked(f"host {host!r} is not in {ALLOWLIST_ENV}")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_and_check(host, port)
    return host


async def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = MAX_IMAGE_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    headers: dict[str, str] | None = None,
    transport: Any = None,
) -> tuple[bytes, str]:
    """Fetch `url` with SSRF checks applied to every hop.

    Returns (content, content_type). Redirects are followed MANUALLY --
    follow_redirects=True is what let a public URL bounce to an internal one
    without anything looking again.
    """
    current = url
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,  # C1: we follow them ourselves, checking each hop
        headers=headers or {},
        transport=transport,
    ) as client:
        for _ in range(max_redirects + 1):
            validate_url(current)  # every hop, not just the first
            async with client.stream("GET", current) as r:
                if r.is_redirect:
                    location = r.headers.get("location")
                    if not location:
                        raise SSRFBlocked(f"redirect from {current!r} with no Location header")
                    current = urljoin(current, location)
                    continue
                r.raise_for_status()

                declared = r.headers.get("content-length")
                if declared and int(declared) > max_bytes:
                    raise SSRFBlocked(f"image is larger than the {max_bytes} byte limit")

                chunks: list[bytes] = []
                total = 0
                async for chunk in r.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise SSRFBlocked(f"image is larger than the {max_bytes} byte limit")
                    chunks.append(chunk)
                content_type = (r.headers.get("content-type") or "image/png").split(";")[0].strip()
                return b"".join(chunks), content_type

    raise SSRFBlocked(f"too many redirects (> {max_redirects}) starting at {url!r}")

"""Session 12, finding C1 — SSRF via /v1/vision.

`_resolve_image_urls` fetched any http(s) URL with follow_redirects=True and
no allowlist, so a caller could make the gateway fetch internal addresses with
the gateway's own identity and network position, and get the bytes back
base64'd into the model's context.

These tests are network-free: literal IPs resolve locally through
getaddrinfo(), and redirect chains are driven with httpx.MockTransport.
"""

from __future__ import annotations

import httpx
import pytest

from glc.security import ssrf
from glc.security.ssrf import SSRFBlocked

# The prize. Category 4 lists the encodings that get you here.
METADATA = "169.254.169.254"


# ── the addresses that matter, in every spelling ────────────────────────────


@pytest.mark.parametrize(
    "url,label",
    [
        (f"http://{METADATA}/latest/meta-data/", "cloud metadata, plainly"),
        ("http://127.0.0.1:8111/v1/control/kill", "loopback: the gateway's own control plane"),
        ("http://localhost:8111/healthz", "loopback by name"),
        ("http://10.0.0.5/", "private (10/8)"),
        ("http://192.168.1.1/", "private (192.168/16)"),
        ("http://172.16.0.1/", "private (172.16/12)"),
        ("http://[::1]/", "IPv6 loopback"),
        ("http://[fe80::1]/", "IPv6 link-local"),
        ("http://[fd00::1]/", "IPv6 unique-local"),
        ("http://0.0.0.0/", "unspecified"),
        (f"http://[::ffff:{METADATA}]/", "IPv4-mapped IPv6: metadata wearing a v6 hat"),
    ],
)
def test_internal_addresses_are_refused(url, label):
    with pytest.raises(SSRFBlocked):
        ssrf.validate_url(url)


def test_decimal_encoded_metadata_is_refused():
    """http://2852039166/ is 169.254.169.254 written as one integer. Checking
    the resolved ADDRESS rather than the host text catches every encoding at
    once -- they all resolve to the same number."""
    try:
        import socket

        socket.getaddrinfo("2852039166", 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        pytest.skip("this resolver does not accept integer-form hosts")
    with pytest.raises(SSRFBlocked):
        ssrf.validate_url("http://2852039166/")


# ── the shape of the URL ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "ftp://internal/secrets",
        "data:text/plain,hi",
    ],
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(SSRFBlocked, match="scheme"):
        ssrf.validate_url(url)


def test_credentials_in_the_url_are_refused():
    with pytest.raises(SSRFBlocked, match="credentials"):
        ssrf.validate_url("http://user:pass@93.184.216.34/img.png")


def test_a_public_address_is_allowed():
    assert ssrf.validate_url("http://93.184.216.34/img.png") == "93.184.216.34"


# ── the allowlist ───────────────────────────────────────────────────────────


def test_allowlist_when_set_excludes_everything_else(monkeypatch):
    monkeypatch.setenv(ssrf.ALLOWLIST_ENV, "images.example.com")
    with pytest.raises(SSRFBlocked, match="not in"):
        ssrf.validate_url("http://93.184.216.34/img.png")


def test_allowlist_never_widens_access(monkeypatch):
    """Even allowlisted, an internal address stays refused."""
    monkeypatch.setenv(ssrf.ALLOWLIST_ENV, "localhost")
    with pytest.raises(SSRFBlocked):
        ssrf.validate_url("http://localhost/img.png")


# ── redirects: re-checked on every hop ──────────────────────────────────────


def _redirect_to(target: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "93.184.216.34":
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(200, content=b"should never get here")

    return httpx.MockTransport(handler)


async def test_redirect_to_metadata_is_refused():
    """The attack follow_redirects=True enabled: a perfectly public URL that
    302s to the metadata service. Checking only the first URL misses it."""
    with pytest.raises(SSRFBlocked, match="link-local"):
        await ssrf.fetch(
            "http://93.184.216.34/img.png",
            transport=_redirect_to(f"http://{METADATA}/latest/meta-data/"),
        )


async def test_redirect_to_loopback_is_refused():
    with pytest.raises(SSRFBlocked, match="loopback"):
        await ssrf.fetch(
            "http://93.184.216.34/img.png",
            transport=_redirect_to("http://127.0.0.1:8111/v1/control/kill"),
        )


async def test_redirect_chains_are_bounded():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://93.184.216.34/next"})

    with pytest.raises(SSRFBlocked, match="too many redirects"):
        await ssrf.fetch("http://93.184.216.34/img.png", transport=httpx.MockTransport(handler))


# ── the honest path, and bounds ─────────────────────────────────────────────


async def test_a_public_image_is_fetched():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"\x89PNG-bytes", headers={"content-type": "image/png"})

    content, mime = await ssrf.fetch("http://93.184.216.34/img.png", transport=httpx.MockTransport(handler))

    assert content == b"\x89PNG-bytes"
    assert mime == "image/png"


async def test_an_oversized_image_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000, headers={"content-type": "image/png"})

    with pytest.raises(SSRFBlocked, match="larger than"):
        await ssrf.fetch("http://93.184.216.34/img.png", transport=httpx.MockTransport(handler), max_bytes=1000)


async def test_a_lying_content_length_does_not_get_past_the_cap():
    """The declared length is a hint, not a promise; the stream is capped too."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000, headers={"content-length": "10"})

    with pytest.raises(SSRFBlocked, match="larger than"):
        await ssrf.fetch("http://93.184.216.34/img.png", transport=httpx.MockTransport(handler), max_bytes=1000)


# ── end to end, through the endpoint the finding actually names ─────────────


def test_vision_endpoint_refuses_a_metadata_url(app_client, install_token):
    """C1 as reported: POST /v1/vision pointed at the cloud metadata service."""
    r = app_client.post(
        "/v1/vision",
        headers={"Authorization": f"Bearer {install_token}"},
        json={"prompt": "what is this?", "image": f"http://{METADATA}/latest/meta-data/"},
    )

    assert r.status_code == 400
    assert "refusing to fetch image url" in r.text


def test_vision_endpoint_refuses_loopback(app_client, install_token):
    r = app_client.post(
        "/v1/vision",
        headers={"Authorization": f"Bearer {install_token}"},
        json={"prompt": "what is this?", "image": "http://127.0.0.1:8111/v1/status"},
    )
    assert r.status_code == 400


def test_blocked_vision_fetch_is_audited(app_client, install_token):
    from glc.audit import query

    app_client.post(
        "/v1/vision",
        headers={"Authorization": f"Bearer {install_token}"},
        json={"prompt": "what is this?", "image": f"http://{METADATA}/latest/meta-data/"},
    )

    events = [r["event_type"] for r in query(limit=20)]
    assert "ssrf_blocked" in events

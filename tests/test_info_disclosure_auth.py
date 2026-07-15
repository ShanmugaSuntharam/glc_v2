"""Session 12, finding A2: /v1/status, /v1/providers, /v1/capabilities,
/v1/cost/by_agent, /v1/calls, /docs, and /openapi.json leaked provider
config, usage, and the full route map with no auth at all. Fix: gate
the five data endpoints behind the install token; disable docs/openapi
by default (opt in via GLC_ENABLE_DOCS=1).
"""

from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    "path",
    ["/v1/status", "/v1/providers", "/v1/capabilities", "/v1/cost/by_agent", "/v1/calls"],
)
def test_info_endpoint_without_token_is_unauthorized(app_client, path):
    r = app_client.get(path)
    assert r.status_code == 401


@pytest.mark.parametrize(
    "path",
    ["/v1/status", "/v1/providers", "/v1/capabilities", "/v1/cost/by_agent", "/v1/calls"],
)
def test_info_endpoint_with_valid_token_passes_auth(app_client, install_token, path):
    h = {"Authorization": f"Bearer {install_token}"}
    r = app_client.get(path, headers=h)
    assert r.status_code == 200


def test_docs_disabled_by_default(app_client):
    assert app_client.get("/docs").status_code == 404
    assert app_client.get("/redoc").status_code == 404
    assert app_client.get("/openapi.json").status_code == 404


def test_docs_enabled_via_env_var(monkeypatch):
    """GLC_ENABLE_DOCS=1 opts back in (e.g. for local dev). Requires a
    fresh import of glc.main since the FastAPI app is built at import time."""
    import sys

    monkeypatch.setenv("GLC_ENABLE_DOCS", "1")
    sys.modules.pop("glc.main", None)
    try:
        import glc.main as m

        assert m.app.docs_url == "/docs"
        assert m.app.openapi_url == "/openapi.json"
    finally:
        sys.modules.pop("glc.main", None)

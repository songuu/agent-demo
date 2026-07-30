from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Final

from fastapi.responses import HTMLResponse, Response

_ALLOWED_ASSETS: Final = frozenset({"index.html", "app.css", "app.js"})
_SECURITY_HEADERS: Final = {
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


@lru_cache(maxsize=len(_ALLOWED_ASSETS))
def _read_asset(name: str) -> str:
    if name not in _ALLOWED_ASSETS:
        raise ValueError(f"Unknown frontend asset: {name}")
    resource = files("agent_platform.api").joinpath("frontend", name)
    return resource.read_text(encoding="utf-8")


def frontend_page() -> HTMLResponse:
    return HTMLResponse(
        _read_asset("index.html"),
        headers=dict(_SECURITY_HEADERS),
    )


def frontend_stylesheet() -> Response:
    return Response(
        _read_asset("app.css"),
        media_type="text/css",
        headers=dict(_SECURITY_HEADERS),
    )


def frontend_script() -> Response:
    return Response(
        _read_asset("app.js"),
        media_type="application/javascript",
        headers=dict(_SECURITY_HEADERS),
    )

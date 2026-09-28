"""HTTP middleware: request IDs and security headers (pure ASGI, no BaseHTTPMiddleware overhead)."""

import re
import uuid

import structlog

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# The SPA loads its own bundle plus Google Fonts; nothing else. The API only returns JSON.
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)


class RequestContextMiddleware:
    """Tags every request with an id: bound into all log lines and echoed as ``X-Request-ID``."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        async def send_with_id(message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            structlog.contextvars.clear_contextvars()


class SecurityHeadersMiddleware:
    """Baseline browser security headers on every response (HSTS only when served over TLS in production)."""

    def __init__(self, app, *, hsts: bool) -> None:
        self.app = app
        self.headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"strict-origin-when-cross-origin"),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
            (b"content-security-policy", _CSP.encode()),
            (b"cross-origin-opener-policy", b"same-origin"),
        ]
        if hsts:
            self.headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        docs = scope.get("path", "").endswith(("/docs", "/redoc"))

        async def send_with_headers(message) -> None:
            if message["type"] == "http.response.start":
                present = {name.lower() for name, _ in message.get("headers", [])}
                extra = [(n, v) for n, v in self.headers if n not in present]
                if docs:  # Swagger/ReDoc (development only) load their UI from a CDN
                    extra = [(n, v) for n, v in extra if n != b"content-security-policy"]
                message.setdefault("headers", []).extend(extra)
            await send(message)

        await self.app(scope, receive, send_with_headers)

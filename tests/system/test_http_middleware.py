from fastapi import FastAPI
from fastapi.testclient import TestClient

from system.http_middleware import RequestContextMiddleware, SecurityHeadersMiddleware


def _client(hsts: bool = False) -> TestClient:
    app = FastAPI()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "yes"}

    app.add_middleware(SecurityHeadersMiddleware, hsts=hsts)
    app.add_middleware(RequestContextMiddleware)
    return TestClient(app)


def test_security_headers_on_every_response():
    response = _client().get("/ping")
    for header in ("x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy"):
        assert header in response.headers
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "strict-transport-security" not in response.headers
    assert "strict-transport-security" in _client(hsts=True).get("/ping").headers


def test_request_id_is_generated_or_propagated_and_sanitized():
    client = _client()
    assert len(client.get("/ping").headers["x-request-id"]) == 32
    assert client.get("/ping", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"] == "abc-123"
    injected = client.get("/ping", headers={"X-Request-ID": "bad id\r\nx: y"}).headers["x-request-id"]
    assert injected != "bad id\r\nx: y" and len(injected) == 32


def test_readiness_reports_database_state(monkeypatch):
    from unittest.mock import AsyncMock

    from api.v1 import base

    app = FastAPI()
    app.include_router(base.router)
    client = TestClient(app)
    monkeypatch.setattr(base.db_manager, "check_connection", AsyncMock(return_value=None))
    assert client.get("/health/ready").json() == {"status": "ok", "database": "ok"}
    monkeypatch.setattr(base.db_manager, "check_connection", AsyncMock(side_effect=ConnectionRefusedError()))
    ready = client.get("/health/ready")
    assert ready.status_code == 503 and ready.json()["database"] == "unreachable"

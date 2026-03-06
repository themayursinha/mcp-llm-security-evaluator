from typing import Optional

from fastapi.testclient import TestClient

import app.api as api_module


def test_health_endpoint():
    client = TestClient(api_module.app)

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert "timestamp" in payload


def test_evaluate_requires_api_key_when_enabled(monkeypatch):
    client = TestClient(api_module.app)

    async def fake_run_evaluation_task(
        profile: str, provider: str, model: Optional[str] = None
    ) -> None:
        return None

    monkeypatch.setattr(api_module.Config, "API_AUTH_REQUIRED", True)
    monkeypatch.setattr(api_module.Config, "API_KEY", "test-key")
    monkeypatch.setattr(api_module, "run_evaluation_task", fake_run_evaluation_task)

    unauthorized = client.post(
        "/evaluate",
        json={"profile": "default", "provider": "mock"},
    )
    authorized = client.post(
        "/evaluate",
        headers={"X-API-Key": "test-key"},
        json={"profile": "default", "provider": "mock"},
    )

    assert unauthorized.status_code == 403
    assert authorized.status_code == 200
    assert authorized.json()["authentication_required"] is True

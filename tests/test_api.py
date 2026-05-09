from typing import Optional
import os

os.environ.setdefault("EVALUATOR_DB_PATH", "/private/tmp/mcp_llm_security_evaluator_api_test.db")

from fastapi.testclient import TestClient  # noqa: E402

import app.api as api_module  # noqa: E402


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


def test_reports_ui_serves_history_page():
    client = TestClient(api_module.app)

    response = client.get("/ui/reports")

    assert response.status_code == 200
    assert "Report History" in response.text


def test_report_history_endpoints_return_saved_reports():
    api_module.create_db_and_tables()
    saved = api_module.save_report_to_db(
        {
            "evaluation_summary": {
                "overall_security_score": 91.0,
                "mcp_security_score": 88.0,
                "leakage_detected": 0,
                "total_tests": 3,
                "execution_time": 0.25,
            },
            "provider_info": {"provider": "mock", "is_mock": True},
            "overall_security_score": 91.0,
            "recommendations": [],
        }
    )
    client = TestClient(api_module.app)

    reports = client.get("/reports?limit=1")
    report_detail = client.get(f"/reports/{saved.id}")
    trends = client.get("/trends?limit=1")

    assert reports.status_code == 200
    assert reports.json()[0]["id"] == saved.id
    assert report_detail.status_code == 200
    assert report_detail.json()["evaluation_summary"]["overall_security_score"] == 91.0
    assert trends.status_code == 200
    assert trends.json()[0]["overall_score"] == 91.0

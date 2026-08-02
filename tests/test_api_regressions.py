"""Regression tests for API runtime and path-safety behavior."""

import os

os.environ.setdefault("DATABASE_PATH", ":memory:")

from fastapi.testclient import TestClient

from threatxtension.api import main as api_main
from threatxtension.workflow.state import WorkflowStatus


def test_trigger_scan_response_does_not_reference_upload_file(monkeypatch):
    """URL scans should return a response without touching an upload-only variable."""

    async def noop_workflow(url: str, extension_id: str):
        api_main.scan_status[extension_id] = "completed"

    api_main.scan_status.clear()
    api_main.scan_results.clear()
    monkeypatch.setattr(api_main.db, "get_scan_result", lambda extension_id: None)
    monkeypatch.setattr(api_main, "run_analysis_workflow", noop_workflow)

    client = TestClient(api_main.app)
    response = client.post(
        "/api/scan/trigger",
        json={"url": "a" * 32, "force": False},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["extension_id"] == "a" * 32
    assert body["status"] == "running"
    assert "filename" not in body


def test_upload_route_registered_once():
    """FastAPI should have a single handler for the upload endpoint."""

    upload_routes = [
        route
        for route in api_main.app.routes
        if getattr(route, "path", None) == "/api/scan/upload"
        and "POST" in getattr(route, "methods", set())
    ]

    assert len(upload_routes) == 1


def test_security_score_handles_chromestats_analysis():
    """Chrome Stats risk should not crash score calculation."""

    state = {
        "analysis_results": {
            "chromestats_analysis": {
                "overall_risk_level": "high",
                "api_risk_analysis": {
                    "has_api_risk_data": True,
                    "risk_impact": 3,
                    "risk_likelihood": 2,
                },
                "risk_indicators": ["removed from store", "high permission risk"],
            }
        },
        "manifest_data": {"name": "Example", "description": "Example extension"},
        "extension_metadata": {"rating": "4.8", "users": "100,000"},
        "status": WorkflowStatus.COMPLETED.value,
    }

    score = api_main.calculate_security_score(state)

    assert isinstance(score, int)
    assert 0 <= score <= 100


def test_score_increases_when_risk_increases():
    """The public score should be higher for a more dangerous extension."""

    safe_state = {
        "analysis_results": {},
        "manifest_data": {
            "name": "Example",
            "description": "Example extension",
            "content_security_policy": {"extension_pages": "script-src 'self'"},
            "update_url": "https://clients2.google.com/service/update2/crx",
        },
        "extension_metadata": {"rating": "4.8", "user_count": 1_000_000},
    }
    dangerous_state = {
        **safe_state,
        "analysis_results": {
            "virustotal_analysis": {
                "enabled": True,
                "summary": {"threat_level": "malicious"},
                "total_malicious": 1,
            }
        },
    }

    safe_score = api_main.calculate_security_score(safe_state)
    dangerous_score = api_main.calculate_security_score(dangerous_state)

    assert dangerous_score > safe_score
    assert api_main.determine_overall_risk(dangerous_state) == "high"


def test_overall_risk_bands_cover_critical(monkeypatch):
    """All four bands must be reachable, including the `critical` level."""

    bands = {
        0: "low",
        15: "low",
        16: "medium",
        35: "medium",
        36: "high",
        60: "high",
        61: "critical",
        100: "critical",
    }

    for score, expected in bands.items():
        monkeypatch.setattr(api_main, "calculate_security_score", lambda _state, s=score: s)
        assert api_main.determine_overall_risk({}) == expected


def test_directory_containment_rejects_prefix_sibling(tmp_path):
    """A sibling path with the same prefix must not pass the containment check."""

    base = tmp_path / "extension"
    sibling = tmp_path / "extension_evil"
    base.mkdir()
    sibling.mkdir()

    assert api_main._is_within_directory(str(base), str(base / "manifest.json"))
    assert not api_main._is_within_directory(str(base), str(sibling / "secret.txt"))

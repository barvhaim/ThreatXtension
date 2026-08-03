"""Regression tests for file-viewer lookups after an API restart.

`/api/scan/files/{id}` and `/api/scan/file/{id}/{path}` used to read the
in-memory `scan_results` cache directly. That cache only holds scans performed
since the process started, so reopening an older scan from history returned 404
even though the row was in the database and the extracted files were on disk.
The endpoints only worked if some other request had warmed the cache first.
"""

import json

from fastapi.testclient import TestClient

from threatxtension.api import main as api_main


EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


def _extracted(tmp_path):
    extracted = tmp_path / f"extracted_{EXT_ID}"
    extracted.mkdir()
    (extracted / "manifest.json").write_text(json.dumps({"name": "demo"}))
    (extracted / "background.js").write_text("console.log('hi');\n")
    return extracted


def _cold_client(monkeypatch, extracted, *, in_db=True):
    """A client whose in-memory cache is empty, as after a restart."""
    monkeypatch.setattr(api_main, "scan_results", {})
    row = {"extension_id": EXT_ID, "extracted_path": str(extracted), "status": "completed"}
    monkeypatch.setattr(api_main.db, "get_scan_result", lambda ext: row if in_db else None)
    return TestClient(api_main.app)


def test_file_list_falls_back_to_database(monkeypatch, tmp_path):
    client = _cold_client(monkeypatch, _extracted(tmp_path))

    response = client.get(f"/api/scan/files/{EXT_ID}")

    assert response.status_code == 200
    assert sorted(response.json()["files"]) == ["background.js", "manifest.json"]


def test_file_content_falls_back_to_database(monkeypatch, tmp_path):
    client = _cold_client(monkeypatch, _extracted(tmp_path))

    response = client.get(f"/api/scan/file/{EXT_ID}/background.js")

    assert response.status_code == 200
    assert response.json()["content"] == "console.log('hi');\n"


def test_unknown_extension_still_404s(monkeypatch, tmp_path):
    client = _cold_client(monkeypatch, _extracted(tmp_path), in_db=False)

    assert client.get(f"/api/scan/files/{EXT_ID}").status_code == 404
    assert client.get(f"/api/scan/file/{EXT_ID}/background.js").status_code == 404


def test_traversal_still_blocked_after_fallback(monkeypatch, tmp_path):
    """The DB fallback must not become a way around the containment check."""
    secret = tmp_path / "secret.txt"
    secret.write_text("do not read me")
    client = _cold_client(monkeypatch, _extracted(tmp_path))

    response = client.get(f"/api/scan/file/{EXT_ID}/../secret.txt")

    assert response.status_code in (403, 404)
    assert "do not read me" not in response.text


def test_resolver_populates_cache(monkeypatch, tmp_path):
    """A hit is cached so repeat views don't re-query the database."""
    extracted = _extracted(tmp_path)
    monkeypatch.setattr(api_main, "scan_results", {})
    calls = []

    def counting_get(ext):
        calls.append(ext)
        return {"extension_id": ext, "extracted_path": str(extracted)}

    monkeypatch.setattr(api_main.db, "get_scan_result", counting_get)

    assert api_main.resolve_scan_result(EXT_ID) is not None
    assert api_main.resolve_scan_result(EXT_ID) is not None
    assert len(calls) == 1

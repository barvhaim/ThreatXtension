"""Tests built from inert synthetic extensions and mocked external services."""

import json
from pathlib import Path

import pytest

from threatxtension.core.analyzers.chromestats import ChromeStatsAnalyzer
from threatxtension.core.analyzers.entropy import EntropyAnalyzer
from threatxtension.core.analyzers.permissions import PermissionsAnalyzer
from threatxtension.core.analyzers.sast import JavaScriptAnalyzer
from threatxtension.core.manifest_parser import ManifestParser
from threatxtension.core.security_scorer import SecurityScorer


FIXTURES = Path(__file__).parent / "fixtures"
SAFE_EXTENSION = FIXTURES / "safe_extension"
RISKY_EXTENSION = FIXTURES / "risky_extension"


def test_manifest_parser_separates_permissions_and_scripts():
    """The safe fixture should parse without executing its JavaScript."""

    manifest = ManifestParser(SAFE_EXTENSION).parse()

    assert manifest is not None
    assert manifest["permissions"] == ["storage"]
    assert manifest["host_permissions"] == ["https://example.com/*"]
    assert manifest["background"] == {
        "type": "service_worker",
        "service_worker": "background.js",
        "type_module": False,
    }
    assert manifest["content_security_policy"].startswith("script-src 'self'")


def test_manifest_parser_rejects_invalid_synthetic_manifest(tmp_path):
    """Malformed fixture data should fail before any analyzer is invoked."""

    (tmp_path / "manifest.json").write_text("{not valid json", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        ManifestParser(tmp_path).parse()


def test_sast_discovers_only_manifest_referenced_javascript():
    """SAST file discovery can be tested without invoking Semgrep or JavaScript."""

    manifest = ManifestParser(RISKY_EXTENSION).parse()

    assert manifest is not None
    files = JavaScriptAnalyzer._extract_javascript_files(str(RISKY_EXTENSION), manifest)

    assert files == [str(RISKY_EXTENSION / "background.js")]


def test_entropy_analyzer_distinguishes_safe_and_obfuscated_fixtures():
    """Inert risky text should trigger obfuscation patterns without being executed."""

    analyzer = EntropyAnalyzer()

    safe = analyzer.analyze(str(SAFE_EXTENSION))
    risky = analyzer.analyze(str(RISKY_EXTENSION))

    assert safe is not None
    assert risky is not None
    assert safe["summary"]["overall_risk"] == "low"
    assert safe["summary"]["obfuscation_detected"] is False
    assert risky["summary"]["overall_risk"] == "high"
    assert risky["summary"]["obfuscation_detected"] is True
    assert set(risky["summary"]["pattern_summary"]) >= {"eval_usage", "jsfuck_pattern"}


def test_permissions_host_analysis_flags_all_urls_without_llm():
    """The deterministic host-permission rule should not require an LLM response."""

    result = PermissionsAnalyzer()._analyze_host_permissions(["<all_urls>"])

    assert result is not None
    assert "Critical host permission detected" in result
    assert "<all_urls>" in result


def test_chromestats_analysis_uses_mocked_api_data(monkeypatch):
    """ChromeStats behavior should be testable without network access or a real extension."""

    monkeypatch.setenv("CHROMESTATS_API_KEY", "synthetic-test-key")
    analyzer = ChromeStatsAnalyzer()
    fake_response = {
        "risk": {
            "riskImpact": 3,
            "riskLikelihood": 3,
            "riskImpactReasons": [],
            "riskLikelihoodReasons": [
                {
                    "reason": "removed-from-store",
                    "severity": "Critical",
                    "description": "Removed from the store",
                    "risk": 10,
                }
            ],
        }
    }
    monkeypatch.setattr(analyzer, "_make_api_request", lambda *args, **kwargs: fake_response)

    result = analyzer.analyze(
        extension_dir=str(RISKY_EXTENSION),
        metadata={"extension_id": "a" * 32},
    )

    assert result is not None
    assert result["enabled"] is True
    assert result["overall_risk_level"] == "critical"
    assert result["api_risk_analysis"]["risk_score"] == 15
    assert any("Removed from the store" in item for item in result["risk_indicators"])


def test_synthetic_risky_extension_scores_higher_than_safe_extension():
    """Composed synthetic analyzer outputs should preserve the public score direction."""

    safe_manifest = ManifestParser(SAFE_EXTENSION).parse()
    risky_manifest = ManifestParser(RISKY_EXTENSION).parse()
    entropy = EntropyAnalyzer()
    scorer = SecurityScorer()

    assert safe_manifest is not None
    assert risky_manifest is not None
    safe = scorer.calculate_score(
        {
            "manifest": safe_manifest,
            "entropy_analysis": entropy.analyze(str(SAFE_EXTENSION)),
            "permissions_analysis": {
                "permissions_details": {"storage": {"is_reasonable": True}},
                "host_permissions_analysis": "No critical host permissions detected",
            },
        }
    )
    risky = scorer.calculate_score(
        {
            "manifest": risky_manifest,
            "entropy_analysis": entropy.analyze(str(RISKY_EXTENSION)),
            "permissions_analysis": {
                "permissions_details": {
                    permission: {"is_reasonable": False}
                    for permission in risky_manifest["permissions"]
                },
                "host_permissions_analysis": "Critical host permission: <all_urls>",
            },
            "javascript_analysis": {
                "sast_findings": {"background.js": [{"extra": {"severity": "CRITICAL"}}]}
            },
        }
    )

    assert safe["security_score"] < risky["security_score"]
    assert safe["risk_level"] == "low"
    assert risky["risk_level"] in {"high", "critical"}

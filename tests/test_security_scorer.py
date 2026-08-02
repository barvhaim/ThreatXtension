"""Regression tests for the central risk score."""

from threatxtension.core.security_scorer import SecurityScorer


def test_central_score_increases_when_risk_increases():
    """A dangerous result must score higher than an empty, low-risk result."""

    scorer = SecurityScorer()
    safe = scorer.calculate_score({})
    dangerous = scorer.calculate_score(
        {
            "virustotal_analysis": {
                "enabled": True,
                "summary": {"threat_level": "malicious"},
                "total_malicious": 1,
            }
        }
    )

    assert safe["security_score"] == 0
    assert safe["risk_level"] == "low"
    assert dangerous["security_score"] > safe["security_score"]
    assert dangerous["risk_level"] == "high"

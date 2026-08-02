# Security Scoring

[← Back to Quickstart](../quickstart.md) · [Architecture Overview](overview.md)

Source: `src/threatxtension/core/security_scorer.py`

The `SecurityScorer` converts raw analyzer output into a single risk score.
This is deliberate: the LLM writes prose, but the *score and risk level are never left to the LLM*.
The scorer runs first inside `SummaryGenerator.generate()`, and its result is stamped onto the
executive summary even if the LLM call fails.

## The model

The scorer **accumulates risk points** across seven categories and caps the total at 100:
`security_score = min(100, total_risk)`. Higher = more dangerous.

| Category | Max points | Source analyzer |
|----------|-----------|-----------------|
| `sast` | 60 | Semgrep findings (severity-weighted) |
| `virustotal` | 50 | AV engine detections |
| `permissions` | 30 | Unreasonable / high-risk manifest permissions |
| `entropy` | 30 | Obfuscated / packed code |
| `chromestats` | 28 | Behavioral threat intelligence |
| `webstore` | 5 | Rating & user-count reputation |
| `manifest` | 5 | Missing CSP, deprecated MV2 |

> The category maxima sum to >100 on purpose. Any single strong signal (e.g. a VirusTotal hit)
> can push an extension into the danger zone by itself.

## Risk bands

```
 0–15   → low       (green)
16–35   → medium    (yellow)
36–60   → high      (orange)
61–100  → critical  (red)
```

Bands are intentionally tight. As the docstring notes, VirusTotal and SAST may *both* be absent
(VT disabled, or no JS files to scan), so the remaining analyzers alone must be able to lift a
borderline extension out of the "low" band.

## Notable scoring rules

- **SAST severities** map to points per finding: `CRITICAL`=15, `ERROR`=12, `WARNING`=5, `INFO`=1,
  plus a *bonus penalty* of +15 (≥5 critical) or +30 (≥10 critical).
- **Permissions**: a permission flagged `is_reasonable=False` costs 5 pts, or 10 if it's in the
  `HIGH_RISK_PERMISSIONS` set (`debugger`, `webRequest`, `cookies`, `nativeMessaging`, `proxy`,
  `management`, `desktopCapture`, `clipboardRead`, etc.). A `<all_urls>` / `*://*/*` host pattern
  adds a flat +15.
- **VirusTotal**: any malicious detection → instant 50; suspicious-only → 25.
- **Entropy**: 10 pts per obfuscated file (cap 20) + 5 pts per suspicious file (cap 10) + 10 if
  ≥3 high-risk patterns.
- **ChromeStats**: uses the analyzer's own `total_risk_score`, capped at 28.
- **Manifest**: missing CSP +3, deprecated Manifest V2 +2.

## Output shape

`calculate_score()` returns:

```python
{
  "security_score": 28,           # 0–100, higher is more dangerous
  "risk_level": "medium",        # low | medium | high | critical
  "total_risk_points": 28,
  "risk_breakdown": {"sast": 12, "permissions": 10, ...},  # points per category
  "risk_details": {...},          # per-category human-readable detail dicts
  "max_possible_risk": 208,       # sum of WEIGHTS
}
```

`SummaryGenerator` merges `security_score`, `overall_risk_level`, `risk_breakdown`,
`risk_details`, and `total_risk_points` into the final executive summary object.

## Tuning

To adjust sensitivity, edit the `WEIGHTS`, `HIGH_RISK_PERMISSIONS`, per-severity point values, or
the band thresholds in `_get_risk_level()`. Because scoring is centralized here, one edit changes
every interface consistently. This is the single most important file to understand before
changing how "risky" any extension appears.

## Related pages
- [Analyzers](../domain/analyzers.md) — what each analyzer produces as scorer input
- [LLM Integration](llm-integration.md) — how the score is combined with LLM prose

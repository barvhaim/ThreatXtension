# Analyzers

[← Back to Quickstart](../quickstart.md) · [Architecture Overview](../architecture/overview.md)

Source: `src/threatxtension/core/analyzers/` and `src/threatxtension/core/extension_analyzer.py`

`ExtensionAnalyzer.analyze()` runs six specialized analyzers and merges their output into a single
dict keyed by analyzer name. That dict becomes `analysis_results` in the
[WorkflowState](../workflows/analysis-pipeline.md#workflowstate) and is fed to both the
[SecurityScorer](../architecture/scoring.md) and the [LLM summary](../architecture/llm-integration.md).

All analyzers extend `BaseAnalyzer` (`analyzers/__init__.py`), an ABC with a single
`analyze(extension_dir, manifest=None, metadata=None) -> Optional[Dict]` method.

## The six analyzers

| Key in `analysis_results` | Class | File | Purpose |
|---------------------------|-------|------|---------|
| `permissions_analysis` | `PermissionsAnalyzer` | `permissions.py` | Rates each manifest permission for reasonableness & risk |
| `javascript_analysis` | `JavaScriptAnalyzer` | `sast.py` | Runs Semgrep with custom rules; returns findings + LLM narrative |
| `webstore_analysis` | `WebstoreAnalyzer` | `webstore.py` | Rating / user count / developer trust signals |
| `virustotal_analysis` | `VirusTotalAnalyzer` | `virustotal.py` | File-hash reputation against VirusTotal |
| `entropy_analysis` | `EntropyAnalyzer` | `entropy.py` | Shannon entropy + pattern matching for obfuscation |
| `chromestats_analysis` | `ChromeStatsAnalyzer` | `chromestats.py` | Behavioral threat intel from chrome-stats.com |

### PermissionsAnalyzer

- Loads a reference `data/permissions_db.json` (capability descriptions per permission) and
  `config/sensitive_domains.json` (domain categories used to judge host permissions).
- For each declared permission it asks the LLM (via `permission_analysis.yaml`) whether the
  permission is *reasonable* given the extension's name/description — producing
  `permissions_details[perm] = {is_reasonable, ...}` which the scorer reads directly.
- Separately analyzes `host_permissions`; `<all_urls>` / `*://*/*` is treated as critical.

### JavaScriptAnalyzer (SAST)

- Reads `config/sast_config.json` for exclusion rules and picks a Semgrep config
  (`config/custom_semgrep_rules.yaml` by default). See [Custom Semgrep Rules](semgrep-rules.md).
- Skips third-party/minified/large files (`_should_skip_file`) so scoring focuses on the
  extension's own code, and scans in parallel with a `ThreadPoolExecutor`.
- Returns raw Semgrep `sast_findings` (grouped per file, each with `extra.severity`) **and** an
  LLM-written `sast_analysis` narrative.

### VirusTotalAnalyzer

- Gated by `VIRUSTOTAL_API_KEY`; when absent it returns `{"enabled": false}` and contributes 0 to
  the score. Config in `config/virustotal_config.json`.
- Hashes extension files (SHA-256) and queries VirusTotal; summarizes to a `threat_level`
  (`clean`/`suspicious`/`malicious`), detection counts, and detected malware families.

### EntropyAnalyzer

- Computes Shannon entropy per JS file plus regex pattern matching to flag packed/obfuscated code.
- Returns `obfuscated_files`, `suspicious_files`, and a `summary` with `overall_risk`,
  `obfuscation_detected`, `high_entropy_files`, and a `pattern_summary`.

### ChromeStatsAnalyzer

- Gated by `CHROMESTATS_API_KEY`. Pulls behavioral intelligence (store removal status, install/
  uninstall trends, rating manipulation patterns, developer reputation, API risk scores).
- Produces its own `total_risk_score` (capped at 28 by the scorer), `risk_indicators`, and
  `overall_risk_level`. Config in `config/chromestats_config.json`.

### WebstoreAnalyzer

- Derives simple reputation signals (rating, user count) from the manifest + scraped metadata;
  low weight (max 5 pts) — it's a tiebreaker, not a primary signal.

## Adding a new analyzer

1. Subclass `BaseAnalyzer` in `core/analyzers/`, implement `analyze(...)`.
2. Instantiate it in `ExtensionAnalyzer.__init__` and call it in `analyze()`, adding a new key to
   the returned dict.
3. Add a `_calculate_<name>_risk()` method and a `WEIGHTS` entry in
   [`SecurityScorer`](../architecture/scoring.md) so it affects the score.
4. Optionally add a prompt / narrative to the [summary](../architecture/llm-integration.md).

## Related pages
- [Security Scoring](../architecture/scoring.md)
- [Custom Semgrep Rules](semgrep-rules.md)
- [LLM Integration](../architecture/llm-integration.md)

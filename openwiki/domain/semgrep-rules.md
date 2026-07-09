# Custom Semgrep Rules

[← Back to Quickstart](../quickstart.md) · [Analyzers](analyzers.md)

Sources:
- `src/threatxtension/config/custom_semgrep_rules.yaml` — the ruleset (~90 rules)
- `src/threatxtension/config/sast_config.json` — scan configuration & exclusions

The SAST layer's value comes from a **purpose-built Semgrep ruleset** targeting malicious *browser
extension* behavior — particularly **banking fraud, credential theft, cookie stealing, and data
exfiltration** — rather than generic code smells. Rules carry MITRE ATT&CK and CWE references.

## Rule themes

The ruleset groups rules by malicious capability. Representative examples:

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `banking.fake_overlay.zindex` | ERROR | Fake UI overlay / login button (high z-index capture) |
| `banking.form_hijack.submit_intercept` | ERROR | Form submit interception + exfiltration |
| `banking.cred_sniff.password_input_hooks` | ERROR | Event hooks on password fields |
| `banking.ext.webrequest.redirect` | ERROR | `chrome.webRequest` redirect/modify (hijack MFA/transactions) |
| `banking.net_sniff.override_fetch_xhr` | ERROR | Overriding `fetch`/XHR prototypes for global sniffing |
| `banking.auto_transfer.silent_payment` | CRITICAL | Silent payment/transfer without consent |
| `banking.mobserver.dynamic_dom_hook` | WARNING | `MutationObserver` used for dynamic overlay/exfil |
| `banking.exfil.generic_channels` | CRITICAL | Exfiltration via `sendBeacon` / `Image.src` / `fetch` |
| `banking.csp.disable_or_weaken` | ERROR | Disabling/weakening CSP |
| `banking.obfuscation.eval_newfunc` | ERROR | `eval()` / `new Function()` with decoding |
| `credential.theft.storage_access` | CRITICAL | Reading `localStorage`/`sessionStorage` for creds |
| `credential.theft.password_extraction` | CRITICAL | Direct password field value extraction |
| `cookie.theft.document_cookie_access` | CRITICAL | Reading `document.cookie` (session hijack) |
| `cookie.theft.cookie_exfiltration` | CRITICAL | Cookie data sent to external server |

Severities map directly to score weights — see [Security Scoring](../architecture/scoring.md)
(`CRITICAL`=15, `ERROR`=12, `WARNING`=5, `INFO`=1 per finding).

## Scan configuration (`sast_config.json`)

The config controls **what gets scanned** so the score reflects the extension's *own* code, not
bundled libraries:

- `exclusion_patterns.path_segments` — skips `lib/`, `vendor/`, `node_modules/`, `dist/`, etc.
- `exclusion_patterns.file_patterns` — skips `*.min.js`, `*.bundle.js`, `chunk-*.js`, etc.
- `exclusion_patterns.library_names` — skips known libs (jquery, bootstrap, lodash, react…).
- `max_file_size_kb` — skips very large files.
- `semgrep_config` / `semgrep_config_options` — selects the active ruleset. A relative path (like
  `config/custom_semgrep_rules.yaml`) is resolved on disk; `p/…` values use Semgrep's registry.

`JavaScriptAnalyzer._should_skip_file()` implements the exclusion logic;
`_get_semgrep_config()` resolves the ruleset path with a fallback to `p/javascript`.

## Extending the rules

1. Add a new rule block to `custom_semgrep_rules.yaml` (Semgrep YAML syntax), with `id`,
   `message`, `severity`, `languages`, `patterns`, and ideally `metadata` (CWE / MITRE).
2. Validate: `uv run semgrep --config src/threatxtension/config/custom_semgrep_rules.yaml <dir>`.
3. Higher-severity rules push scores harder — pick severity intentionally.

## Related pages
- [Analyzers](analyzers.md)
- [Security Scoring](../architecture/scoring.md)

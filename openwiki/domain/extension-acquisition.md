# Extension Acquisition

[← Back to Quickstart](../quickstart.md) · [Analysis Pipeline](../workflows/analysis-pipeline.md)

Sources:
- `src/threatxtension/utils/extension.py` — input classification, extraction, cleanup, hashing
- `src/threatxtension/core/extension_downloader.py` — Web Store download
- `src/threatxtension/core/chromestats_downloader.py` — chrome-stats.com download
- `src/threatxtension/core/manifest_parser.py` — manifest parsing

ThreatXtension accepts **three input kinds** and normalizes them into an extracted directory + a
parsed manifest before analysis. Input classification happens in `extension_path_routing_node`
(see [Analysis Pipeline](../workflows/analysis-pipeline.md)).

## Input classification

`utils/extension.py` provides the routing predicates:

| Predicate | Matches | Route |
|-----------|---------|-------|
| `is_chrome_extension_id` | `^[a-p]{32}$` (Chrome IDs are base16 using letters a–p) | chrome-stats download |
| `is_chrome_extension_store_url` | starts with `https://chromewebstore.google.com/detail/` | metadata scrape → Web Store download |
| `is_local_extension_crx_file` | existing local `.crx` or `.zip` | direct extraction |

Anything else fails the workflow with a descriptive error.

## Download sources

- **Chrome Web Store** (`ExtensionDownloader`): used for store URLs. The downloaded CRX path is
  stored in `downloaded_crx_path` so cleanup deletes it afterward.
- **chrome-stats.com** (`ChromeStatsDownloader`): used for bare extension IDs (requires
  `CHROMESTATS_API_KEY`). Downloads as ZIP for easier extraction and also yields metadata that
  enriches the Web Store metadata.
- **Local file**: extracted directly; `downloaded_crx_path` is intentionally **not** set, so the
  user's file is never deleted by cleanup.

## Extraction

`extract_extension_crx()` handles both formats:

- **`.crx`** — a ZIP with a proprietary header. The code seeks past the first 4 bytes, writes the
  ZIP payload to a temp file, and extracts it.
- **`.zip`** — extracted directly.

Both paths use `_safe_extract_zip()`, which **rejects archive members that would escape the
extraction directory** (Zip Slip / path traversal defense) by comparing `commonpath`. Extraction
targets `EXTENSION_STORAGE_PATH` (default `extensions_storage/`) with a per-PID unique dir name.

## Cleanup safety

- `cleanup_downloaded_crx()` refuses to delete anything outside the storage directory and is
  idempotent (warns if the file is already gone).
- `cleanup_extension_dir()` recursively removes the extracted tree — but only when
  `keep_extracted` is falsy (see the [cleanup semantics](../workflows/analysis-pipeline.md#cleanup-semantics-important)).

## Manifest parsing

`ManifestParser(extension_dir).parse()` reads `manifest.json` and returns the parsed dict
(`manifest_data`), which downstream analyzers and the scorer consult for permissions,
`content_security_policy`, and `manifest_version`.

## Related pages
- [Analysis Pipeline](../workflows/analysis-pipeline.md)
- [Analyzers](analyzers.md)

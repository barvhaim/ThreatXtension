"""Regression tests for `extension_id` in scraped Web Store metadata.

`fetch_metadata()` returned 14 keys but no `extension_id`, so for `--url` input
`ChromeStatsAnalyzer` always bailed out with "Extension ID required" and
contributed 0 of its 28 possible risk points. The chrome-stats metadata
enrichment in `extension_metadata_node` is guarded on the same key, so it was
dead code on the URL path too. Only `--id` input ever populated it.
"""

from threatxtension.core.analyzers.chromestats import ChromeStatsAnalyzer
from threatxtension.core.extension_metadata import ExtensionMetadata


EXT_ID = "mkbgbmpflbnfaggocaefeomjdcllkbak"
STORE_URL = f"https://chromewebstore.google.com/detail/continue-session-bridge/{EXT_ID}"

# Minimal page: fetch_metadata only needs to parse without raising.
PAGE = "<html><body><h1>Continue Session Bridge</h1></body></html>"


def _metadata_for(url, monkeypatch):
    extractor = ExtensionMetadata(extension_url=url)
    monkeypatch.setattr(extractor, "_fetch_page", lambda: PAGE)
    return extractor.fetch_metadata()


def test_fetch_metadata_includes_extension_id(monkeypatch):
    metadata = _metadata_for(STORE_URL, monkeypatch)

    assert metadata is not None
    assert metadata["extension_id"] == EXT_ID


def test_fetch_metadata_handles_url_without_slug(monkeypatch):
    metadata = _metadata_for(f"https://chromewebstore.google.com/detail/{EXT_ID}", monkeypatch)

    assert metadata["extension_id"] == EXT_ID


def test_extension_id_key_always_present(monkeypatch):
    """Absent an ID the key must still exist, so `.get()` callers see None."""
    metadata = _metadata_for("https://example.com/not-a-store-page", monkeypatch)

    assert "extension_id" in metadata
    assert metadata["extension_id"] is None


def test_chromestats_accepts_scraped_metadata(monkeypatch):
    """The scraped dict must satisfy ChromeStatsAnalyzer's ID requirement."""
    metadata = _metadata_for(STORE_URL, monkeypatch)

    analyzer = ChromeStatsAnalyzer()
    monkeypatch.setattr(analyzer, "enabled", True)
    monkeypatch.setattr(analyzer, "_make_api_request", lambda endpoint, params=None: None)

    result = analyzer.analyze("/tmp", None, metadata)

    assert result.get("error") != "Extension ID required for Chrome Stats analysis"

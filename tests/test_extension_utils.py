"""Tests for Chrome extension archive utilities."""

import zipfile
from pathlib import Path

from threatxtension.utils.extension import extract_extension_crx


def test_extract_extension_zip_rejects_zip_slip(tmp_path, monkeypatch):
    """Archive members cannot escape the configured extraction directory."""

    storage_dir = tmp_path / "storage"
    archive_path = tmp_path / "malicious.zip"
    escaped_path = tmp_path / "escaped.txt"

    with zipfile.ZipFile(archive_path, "w") as zip_ref:
        zip_ref.writestr("../escaped.txt", "owned")

    monkeypatch.setenv("EXTENSION_STORAGE_PATH", str(storage_dir))

    assert extract_extension_crx(str(archive_path)) is None
    assert not escaped_path.exists()


def test_extract_extension_zip_accepts_safe_archive(tmp_path, monkeypatch):
    """Normal extension archives should still extract successfully."""

    storage_dir = tmp_path / "storage"
    archive_path = tmp_path / "safe.zip"

    with zipfile.ZipFile(archive_path, "w") as zip_ref:
        zip_ref.writestr("manifest.json", '{"manifest_version": 3, "name": "Safe"}')

    monkeypatch.setenv("EXTENSION_STORAGE_PATH", str(storage_dir))

    extract_dir = extract_extension_crx(str(archive_path))

    assert extract_dir is not None
    assert (Path(extract_dir) / "manifest.json").exists()

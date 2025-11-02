"""
Chrome Extension Utilities

This module provides utilities for extracting, analyzing, and managing Chrome extensions.
"""

import zipfile
import tempfile
import os
import re
import logging
import hashlib
from typing import Optional

logger = logging.getLogger(__name__)


def extract_extension_id_by_url(url):
    """Extract extension ID from Chrome Web Store URL"""
    try:
        # Handle different URL formats
        if "/detail/" in url:
            # Format: https://chromewebstore.google.com/detail/name/id
            parts = url.split("/detail/")
            if len(parts) > 1:
                extension_part = parts[1]
                # Split by '/' and take the last part (the ID)
                extension_id = extension_part.split("/")[-1]
                return extension_id
        elif "id=" in url:
            # Format: https://chromewebstore.google.com/detail/...?id=...
            match = re.search(r"id=([^&]+)", url)
            if match:
                return match.group(1)

        logger.warning("Could not extract extension ID from URL")
        return None

    except Exception as exc:
        logger.error("Error extracting extension ID: %s", exc)
        return None


def calculate_file_hash(file_path: str) -> Optional[str]:
    """Calculate SHA256 hash of downloaded file"""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as exc:
        logger.error("Error calculating file hash: %s", exc)
        return None


def extract_extension_crx(file_path: str) -> Optional[str]:
    """Extract .crx file to a directory"""

    # Create temporary directory for extraction
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"threatxtension_{os.path.basename(file_path)}_")
        logger.info("Extracting .crx file to %s", temp_dir)

        if file_path.endswith(".crx"):
            # CRX files are ZIP files with a different header
            # We need to skip the first few bytes
            with open(file_path, "rb") as f:
                # Skip CRX header (first 4 bytes)
                f.seek(4)
                # Read the ZIP content
                zip_data = f.read()

            temp_zip = os.path.join(temp_dir, "temp.zip")
            with open(temp_zip, "wb") as f:
                f.write(zip_data)

            with zipfile.ZipFile(temp_zip, "r") as zip_ref:
                zip_ref.extractall(temp_dir)

            os.remove(temp_zip)

        elif file_path.endswith(".zip"):
            # Direct ZIP extraction
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)

        else:
            logger.error("Unsupported file format for extraction: %s", file_path)
            return None

        return temp_dir
    except Exception as exc:
        logger.error("Error extracting .crx file: %s", exc)
        return None


def cleanup_extension_dir(temp_dir: str):
    """Remove temporary directory and its contents"""
    try:
        if os.path.exists(temp_dir):
            for root, dirs, files in os.walk(temp_dir, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(temp_dir)
            logger.info("Cleaned up temporary directory: %s", temp_dir)
    except Exception as exc:
        logger.error("Error cleaning up temporary directory: %s", exc)


def is_chrome_extension_store_url(path: str) -> bool:
    """
    Check if the provided path is a valid Chrome Web Store URL

    Example:
        - "https://chromewebstore.google.com/detail/
          fantasypros-win-your-fant/gfbepnlhpkbgbkcebjnfhgjckibfdfkc"

    Args:
        path (str): The URL to check.

    Returns:
        bool: True if the URL matches the Chrome Web Store pattern, False otherwise.
    """
    return path.startswith("https://chromewebstore.google.com/detail/")

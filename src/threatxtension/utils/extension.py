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
            # Format: https://chromewebstore.google.com/detail/name/id or
            # https://chromewebstore.google.com/detail/id
            parts = url.split("/detail/")
            if len(parts) > 1:
                extension_part = parts[1]
                # Split by '/' and take the last part (the ID)
                extension_id = extension_part.split("/")[-1]
                # Remove query parameters (e.g., ?utm_source=...)
                extension_id = extension_id.split("?")[0]
                # Remove any trailing slashes
                extension_id = extension_id.rstrip("/")
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
    """Extract .crx file to a persistent directory for file viewing"""

    # Use persistent storage directory instead of /tmp
    try:
        # Get storage path from environment or use default
        storage_path = os.environ.get("EXTENSION_STORAGE_PATH", "extensions_storage")
        os.makedirs(storage_path, exist_ok=True)
        
        # Create extraction directory with unique name
        base_name = os.path.basename(file_path)
        extract_dir_name = f"extracted_{base_name}_{os.getpid()}"
        extract_dir = os.path.join(storage_path, extract_dir_name)
        os.makedirs(extract_dir, exist_ok=True)
        
        logger.info("Extracting .crx file to persistent storage: %s", extract_dir)

        if file_path.endswith(".crx"):
            # CRX files are ZIP files with a different header
            # We need to skip the first few bytes
            with open(file_path, "rb") as f:
                # Skip CRX header (first 4 bytes)
                f.seek(4)
                # Read the ZIP content
                zip_data = f.read()

            temp_zip = os.path.join(extract_dir, "temp.zip")
            with open(temp_zip, "wb") as f:
                f.write(zip_data)

            with zipfile.ZipFile(temp_zip, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

            os.remove(temp_zip)

        elif file_path.endswith(".zip"):
            # Direct ZIP extraction
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)

        else:
            logger.error("Unsupported file format for extraction: %s", file_path)
            return None

        return extract_dir
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


def cleanup_downloaded_crx(crx_file_path: str):
    """
    Remove a downloaded CRX file with safety checks.

    Only deletes files within the extensions_storage directory.
    Logs warning if file doesn't exist (idempotent).

    Args:
        crx_file_path (str): Path to the CRX file to remove.

    Raises:
        ValueError: If file path is outside extensions_storage directory.
        OSError: If file deletion fails.
    """
    try:
        if not os.path.exists(crx_file_path):
            logger.warning("CRX file does not exist (already cleaned?): %s", crx_file_path)
            return

        # Safety: Only delete files within storage directory
        abs_crx_path = os.path.abspath(crx_file_path)
        storage_path = os.getenv("EXTENSION_STORAGE_PATH", "./extensions_storage")
        abs_storage_path = os.path.abspath(storage_path)

        if not abs_crx_path.startswith(abs_storage_path):
            logger.warning(
                "Refusing to delete CRX file outside storage directory: %s",
                abs_crx_path,
            )
            raise ValueError(f"CRX file path outside storage directory: {abs_crx_path}")

        os.remove(crx_file_path)
        logger.info("Cleaned up CRX file: %s", crx_file_path)

    except Exception as exc:
        logger.error("Error cleaning up CRX file %s: %s", crx_file_path, exc)
        raise


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


def is_local_extension_crx_file(path: str) -> bool:
    """
    Check if the provided path is a local CRX or ZIP file

    Args:
        path (str): The file path to check.

    Returns:
        bool: True if the path is a local .crx or .zip file, False otherwise.
    """
    if not path:
        return False
    return os.path.isfile(path) and (path.lower().endswith(".crx") or path.lower().endswith(".zip"))


def is_chrome_extension_id(path: str) -> bool:
    """
    Check if the provided string is a valid Chrome extension ID.
    
    Chrome extension IDs are 32-character lowercase alphanumeric strings.
    Example: gbbilodpoldeopifonmibfboicpafpjo
    
    Args:
        path (str): The string to check.
        
    Returns:
        bool: True if the string matches Chrome extension ID pattern, False otherwise.
    """
    if not path or not isinstance(path, str):
        return False
    
    # Chrome extension IDs are exactly 32 characters, lowercase letters a-p only
    # (base16 encoding using letters a-p instead of 0-9a-f)
    pattern = r'^[a-p]{32}$'
    return bool(re.match(pattern, path.strip().lower()))

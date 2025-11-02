"""
Chrome Extension Downloader
Downloads Chrome extensions from the Chrome Web Store as CRX or ZIP files
"""

import os
import logging
from typing import Optional, Dict
from datetime import datetime
from dotenv import load_dotenv
import requests
from threatxtension.utils.extension import calculate_file_hash, extract_extension_id_by_url

load_dotenv()
logger = logging.getLogger(__name__)


class ExtensionDownloader:
    """Downloads Chrome extensions from the Chrome Web Store"""

    def __init__(self):
        self.extension_storage_path = os.getenv("EXTENSION_STORAGE_PATH", "./extensions_storage")

    @staticmethod
    def _get_download_url(extension_id: str) -> str:
        """
        Constructs the download URL for the given extension ID

        Args:
            extension_id (str): The ID of the Chrome
            extension to download
        Returns:
            str: The download URL for the extension
        """
        chrome_version = os.getenv("CHROME_VERSION", "118.0")
        download_url = (
            "https://clients2.google.com/service/update2/crx"
            f"?response=redirect&prodversion={chrome_version}"
            "&acceptformat=crx2%2Ccrx3"
            f"&x=id%3D{extension_id}%26uc"
        )
        return download_url

    def _download(self, extension_id: str, download_url: str) -> Optional[Dict]:
        """
        Downloads the extension from the given URL

        Args:
            download_url (str): The URL to download the extension from
        Returns:
            Optional[Dict]: A dictionary containing the extension's metadata and file
                content, or None if download fails
        """
        try:
            logger.info("Downloading extension %s from %s", extension_id, download_url)
            filename = f"{extension_id}.crx"
            file_path = os.path.join(self.extension_storage_path, filename)
            os.makedirs(self.extension_storage_path, exist_ok=True)

            # Download the file
            response = requests.get(download_url, stream=True, timeout=120)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "")
            if (
                "application/x-chrome-extension" not in content_type
                and "application/octet-stream" not in content_type
            ):
                logger.warning("Unexpected content type: %s", content_type)
                return None

            # Save the file
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            file_size = os.path.getsize(file_path)
            logger.info("Downloaded %s to %s (%s bytes)", extension_id, file_path, file_size)

            return {
                "extension_id": extension_id,
                "file_path": file_path,
                "file_size": file_size,
                "download_url": download_url,
            }
        except Exception as exc:
            logger.error("Failed to download from %s: %s", download_url, exc)
            return None

    def download_extension(self, extension_url: str) -> Optional[Dict]:
        """
        Downloads the Chrome extension with the given Chrome Web Store URL

        Args:
            extension_url (str): The URL of the Chrome extension to download

        Returns:
            Optional[Dict]: A dictionary containing the extension's metadata, or None
                if download fails
        """
        try:
            extension_id = extract_extension_id_by_url(extension_url)
            download_url = self._get_download_url(extension_id)
            file_info = self._download(extension_id, download_url)
            if not file_info:
                logger.error("Failed to download extension %s", extension_id)
                return None

            file_hash = calculate_file_hash(file_info["file_path"])
            if not file_hash:
                logger.error("Failed to calculate hash for extension %s", extension_id)
                return None

            file_info["file_hash"] = file_hash
            file_info["download_date"] = datetime.now().strftime("%Y%m%d_%H%M%S")
            return file_info

        except Exception as exc:
            logger.error("Failed to download extension %s: %s", extension_url, exc)
            return None


if __name__ == "__main__":
    # Test the downloader
    test_downloader = ExtensionDownloader()

    EXTENSION_URL = "https://chromewebstore.google.com/detail/2048/ijkmjnaahlnmdjjlbhbjbhlnmadmmlgg"

    result = test_downloader.download_extension(extension_url=EXTENSION_URL)
    if result:
        print(f"Download successful: {result}")
    else:
        print("Download failed")

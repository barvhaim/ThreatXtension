"""
Chrome Stats Extension Downloader

This module provides functionality to download Chrome extensions from chrome-stats.com API.
"""

import os
import logging
import requests
from typing import Optional, Dict, Tuple
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class ChromeStatsDownloader:
    """
    Downloads Chrome extensions using the chrome-stats.com API.
    
    API Documentation: https://chrome-stats.com/api/download
    """
    
    def __init__(self):
        """Initialize the ChromeStatsDownloader."""
        self.api_key = os.getenv("CHROMESTATS_API_KEY")
        self.api_base_url = os.getenv("CHROMESTATS_API_URL", "https://chrome-stats.com")
        self.enabled = bool(self.api_key)
        
        if not self.api_key:
            logger.warning("CHROMESTATS_API_KEY not set. Chrome Stats download will be disabled.")
    
    def _get_extension_details(self, extension_id: str) -> Optional[Dict]:
        """
        Fetch extension details from Chrome Stats API.
        
        Args:
            extension_id: Chrome extension ID
            
        Returns:
            Extension details including manifest and version info
        """
        if not self.enabled:
            return None
            
        try:
            url = f"{self.api_base_url}/api/detail"
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": self.api_key
            }
            params = {"id": extension_id}
            
            logger.info("Fetching extension details for ID: %s", extension_id)
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            logger.info("Successfully fetched extension details")
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error("Failed to fetch extension details: %s", e)
            return None
        except Exception as e:
            logger.error("Error fetching extension details: %s", e)
            return None
    
    def download_extension(
        self, 
        extension_id: str, 
        version: Optional[str] = None,
        file_format: str = "ZIP"
    ) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Download Chrome extension from chrome-stats.com API.
        
        Args:
            extension_id: Chrome extension ID (32 character string)
            version: Specific version to download (optional, uses latest if not specified)
            file_format: File format - "ZIP" or "CRX" (default: "ZIP")
            
        Returns:
            Tuple of (downloaded_file_path, extension_metadata)
            Returns (None, None) if download fails
        """
        if not self.enabled:
            logger.error("Chrome Stats downloader is disabled (API key not configured)")
            return None, None
        
        if file_format not in ["ZIP", "CRX"]:
            logger.error("Invalid file format: %s. Must be ZIP or CRX", file_format)
            return None, None
        
        extension_details = self._get_extension_details(extension_id)
        if not extension_details:
            logger.error("Failed to fetch extension details for ID: %s", extension_id)
            return None, None
        
        if not version:
            version = extension_details.get("version")
            if not version:
                logger.error("Could not determine extension version")
                return None, None
            logger.info("Using latest version: %s", version)
        
        try:
            url = f"{self.api_base_url}/api/download"
            headers = {
                "X-API-Key": self.api_key
            }
            params = {
                "id": extension_id,
                "type": file_format,
                "version": version
            }
            
            logger.info(
                "Downloading extension %s (version %s) as %s", 
                extension_id, version, file_format
            )
            
            response = requests.get(url, headers=headers, params=params, timeout=60, stream=True)
            response.raise_for_status()
            
            file_ext = ".zip" if file_format == "ZIP" else ".crx"
            
            storage_path = os.getenv("EXTENSION_STORAGE_PATH", "./extensions_storage")
            os.makedirs(storage_path, exist_ok=True)
            
            extension_name = extension_details.get("name", "unknown").replace(" ", "_")[:50]
            filename = f"{extension_name}_{extension_id}_{version}{file_ext}"
            file_path = os.path.join(storage_path, filename)
            
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            file_size = os.path.getsize(file_path)
            logger.info("Successfully downloaded extension to %s (%.2f MB)", file_path, file_size / 1024 / 1024)
            
            metadata = {
                "extension_id": extension_id,
                "name": extension_details.get("name"),
                "version": version,
                "description": extension_details.get("description"),
                "full_summary": extension_details.get("fullSummary"),
                "category": extension_details.get("category"),
                "item_category": extension_details.get("itemCategory"),
                "user_count": extension_details.get("userCount"),
                "rating_value": extension_details.get("ratingValue"),
                "rating_count": extension_details.get("ratingCount"),
                "logo": extension_details.get("logo"),
                "url": extension_details.get("url"),
                "website": extension_details.get("website"),
                "author": extension_details.get("author"),
                "payment_type": extension_details.get("paymentType"),
                "is_featured": extension_details.get("isFeatured"),
                "is_trusted_publisher": extension_details.get("isTrustedPublisher"),
                "privacy_policy_url": extension_details.get("privacyPolicyUrl"),
                "platform": extension_details.get("platform"),
                "last_update": extension_details.get("lastUpdate"),
                "creation_date": extension_details.get("creationDate"),
                "size": extension_details.get("size"),
                "supported_languages": extension_details.get("supportedLanguages"),
                "help_url": extension_details.get("helpUrl"),
                "email": extension_details.get("email"),
                "publisher_address": extension_details.get("publisherAddress"),
                "publisher_country": extension_details.get("publisherCountry"),
                "is_download_blocked": extension_details.get("isDownloadBlocked"),
                
                "risk": extension_details.get("risk"),
                "review_summary": extension_details.get("reviewSummary"),
                # Recent reviews (limit to top 5)
                "reviews": extension_details.get("reviews", [])[:5] if extension_details.get("reviews") else [],
                
                "one_week_delta": extension_details.get("oneWeekDelta"),
                "one_day_delta": extension_details.get("oneDayDelta"),
                
                "manifest_json": extension_details.get("manifestJson"),
                "manifest_summary": extension_details.get("manifestSummary"),
                
                "media": extension_details.get("media"),
                "small_banner": extension_details.get("smallBanner"),
                "marquee_banner": extension_details.get("marqueeBanner"),
                "num_screenshots": extension_details.get("numScreenshots"),
                "num_videos": extension_details.get("numVideos"),
                
                "related": extension_details.get("related"),
                "alternatives": extension_details.get("alternatives"),
                
                "cross_platform_data": extension_details.get("crossPlatformData"),
                
                "all_ranks": extension_details.get("allRanks"),
                "one_week_ago_ranks": extension_details.get("oneWeekAgoRanks"),
                
                "download_source": "chrome-stats.com",
                "file_format": file_format,
                "file_size": file_size,
                "as_of_date": extension_details.get("asOfDate"),
            }
            
            return file_path, metadata
            
        except requests.exceptions.RequestException as e:
            logger.error("Failed to download extension: %s", e)
            return None, None
        except Exception as e:
            logger.error("Error downloading extension: %s", e)
            return None, None
    
    def get_available_versions(self, extension_id: str) -> Optional[list]:
        """
        Get list of available versions for an extension.
        
        Args:
            extension_id: Chrome extension ID
            
        Returns:
            List of version strings or None if unavailable
        """
        details = self._get_extension_details(extension_id)
        if details:
            return details.get("version_history", [details.get("version")])
        return None

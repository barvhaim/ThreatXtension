"""
Manifest Parser
"""

import json
from typing import Optional, Dict, Any, List
from pathlib import Path
import logging


logger = logging.getLogger(__name__)


class ManifestParser:
    """
    Parse and extract data from Chrome extension manifest.json

    Supports both Manifest V2 and V3
    """

    def __init__(self, extension_dir):
        """Initialize the ManifestParser."""
        self.extension_dir = extension_dir

    def _extract_permissions(self, manifest: dict) -> List[str]:
        """
        Extract permissions list

        In Manifest V3, some permissions moved to host_permissions
        """
        permissions = manifest.get("permissions", [])

        # Manifest V2 sometimes includes host permissions in permissions array
        # Filter out URL patterns (they should be in host_permissions)
        if manifest.get("manifest_version") == 3:
            permissions = [p for p in permissions if not self._is_url_pattern(p)]

        return permissions

    def _extract_host_permissions(self, manifest: dict) -> List[str]:
        """
        Extract host permissions (URL patterns)

        Manifest V2: URLs in permissions array
        Manifest V3: Separate host_permissions array
        """
        if manifest.get("manifest_version") == 3:
            return manifest.get("host_permissions", [])
        else:
            # V2: Extract URL patterns from permissions
            permissions = manifest.get("permissions", [])
            return [p for p in permissions if self._is_url_pattern(p)]

    @staticmethod
    def _is_url_pattern(permission: str) -> bool:
        """Check if permission is a URL pattern"""
        url_indicators = ["://", "*://", "http://", "https://", "file://", "ftp://"]
        return any(indicator in permission for indicator in url_indicators)

    @staticmethod
    def _extract_content_scripts(manifest: dict) -> List[Dict]:
        """
        Extract content scripts with their configurations

        Returns list of:
        {
            'matches': ['*://example.com/*'],
            'js': ['content.js'],
            'css': ['style.css'],
            'run_at': 'document_idle',
            'all_frames': False
        }
        """
        content_scripts = manifest.get("content_scripts", [])

        structured = []
        for script in content_scripts:
            structured.append(
                {
                    "matches": script.get("matches", []),
                    "exclude_matches": script.get("exclude_matches", []),
                    "js": script.get("js", []),
                    "css": script.get("css", []),
                    "run_at": script.get("run_at", "document_idle"),
                    "all_frames": script.get("all_frames", False),
                    "match_about_blank": script.get("match_about_blank", False),
                }
            )

        return structured

    @staticmethod
    def _extract_background(manifest: dict) -> Optional[Dict]:
        """
        Extract background script/service worker

        Manifest V2: background.scripts or background.page
        Manifest V3: background.service_worker
        """
        background = manifest.get("background")

        if not background:
            return None

        if manifest.get("manifest_version") == 3:
            # V3: Service worker
            return {
                "type": "service_worker",
                "service_worker": background.get("service_worker"),
                "type_module": background.get("type") == "module",
            }
        else:
            # V2: Scripts or page
            return {
                "type": "scripts" if "scripts" in background else "page",
                "scripts": background.get("scripts", []),
                "page": background.get("page"),
                "persistent": background.get("persistent", True),
            }

    @staticmethod
    def _extract_web_accessible_resources(manifest: dict) -> List:
        """
        Extract web accessible resources

        V2: Array of strings
        V3: Array of objects with resources and matches
        """
        war = manifest.get("web_accessible_resources", [])

        if not war:
            return []

        # V3 format: array of objects
        if manifest.get("manifest_version") == 3 and war and isinstance(war[0], dict):
            return war

        # V2 format: array of strings
        return war

    @staticmethod
    def _extract_csp(manifest: dict) -> Optional[str]:
        """
        Extract Content Security Policy

        V2: String
        V3: Object with extension_pages and sandbox
        """
        csp = manifest.get("content_security_policy")

        if not csp:
            return None

        # V3: Object
        if isinstance(csp, dict):
            return csp.get("extension_pages", "")

        # V2: String
        return csp

    @staticmethod
    def get_all_script_files(manifest_data: dict) -> List[str]:
        """
        Get list of all JavaScript files referenced in manifest

        Args:
            manifest_data: Parsed manifest from parse()

        Returns:
            list: All JS file paths
        """
        js_files = []

        # Content scripts
        for script in manifest_data.get("content_scripts", []):
            js_files.extend(script.get("js", []))

        # Background scripts
        background = manifest_data.get("background")
        if background:
            if background.get("type") == "service_worker":
                js_files.append(background["service_worker"])
            else:
                js_files.extend(background.get("scripts", []))

        # Action popup
        action = manifest_data.get("action")
        if action and action.get("default_popup"):
            # Note: Popup is HTML, need to parse it to find JS
            # For now, just note the HTML file
            pass

        return js_files

    @staticmethod
    def get_dangerous_permissions(manifest_data: dict) -> List[str]:
        """
        Get list of potentially dangerous permissions

        Based on LayerX whitepaper examples
        """
        dangerous = []

        all_permissions = manifest_data.get("permissions", []) + manifest_data.get(
            "host_permissions", []
        )

        # Known dangerous permissions
        dangerous_list = [
            "cookies",  # Can steal session cookies
            "webRequest",  # Can intercept/modify requests
            "webRequestBlocking",
            "proxy",  # Can route traffic through attacker
            "debugger",  # Full control over tabs
            "declarativeNetRequest",
            "management",  # Can control other extensions
            "nativeMessaging",  # Can communicate with native apps
            "pageCapture",  # Can capture full page content
            "privacy",  # Can modify privacy settings
            "system.storage",  # Access to storage devices
            "<all_urls>",  # Access to all websites
            "*://*/*",  # Access to all websites
            "http://*/*",  # Access to all HTTP sites
            "https://*/*",  # Access to all HTTPS sites
        ]

        for perm in all_permissions:
            if perm in dangerous_list:
                dangerous.append(perm)

        return dangerous

    def parse(self) -> Optional[Dict[str, Any]]:
        """
        Parse manifest.json from extension directory

        Returns:
            dict: Parsed and structured manifest data

        Raises:
            FileNotFoundError: If manifest.json not found
            json.JSONDecodeError: If manifest.json is invalid
        """
        extension_path = Path(self.extension_dir)
        manifest_path = extension_path / "manifest.json"

        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest.json not found in {self.extension_dir}")

        logger.info(f"Parsing manifest from: {manifest_path}")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                raw_manifest = json.load(f)

            # Extract and structure data
            parsed = {
                # Basic info
                "name": raw_manifest.get("name", "Unknown"),
                "version": raw_manifest.get("version", "Unknown"),
                "manifest_version": raw_manifest.get("manifest_version", 2),
                "description": raw_manifest.get("description", ""),
                # Permissions (CRITICAL for risk scoring)
                "permissions": self._extract_permissions(raw_manifest),
                "host_permissions": self._extract_host_permissions(raw_manifest),
                "optional_permissions": raw_manifest.get("optional_permissions", []),
                # Scripts
                "content_scripts": self._extract_content_scripts(raw_manifest),
                "background": self._extract_background(raw_manifest),
                # UI Components
                "action": raw_manifest.get("action")
                or raw_manifest.get("browser_action")
                or raw_manifest.get("page_action"),
                "options_page": raw_manifest.get("options_page")
                or raw_manifest.get("options_ui", {}).get("page"),
                # Security-relevant fields
                "web_accessible_resources": self._extract_web_accessible_resources(raw_manifest),
                "externally_connectable": raw_manifest.get("externally_connectable"),
                "content_security_policy": self._extract_csp(raw_manifest),
                "update_url": raw_manifest.get("update_url"),
                # Additional
                "icons": raw_manifest.get("icons", {}),
                "homepage_url": raw_manifest.get("homepage_url"),
                "author": raw_manifest.get("author"),
            }

            logger.info(f"Manifest parsed successfully: {parsed['name']} v{parsed['version']}")
            logger.debug(
                f"Permissions: {len(parsed['permissions'])}, Content Scripts: {len(parsed['content_scripts'])}"
            )

            return parsed

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in manifest.json: {e}")
            raise
        except Exception as e:
            logger.error(f"Error parsing manifest: {e}")
            raise

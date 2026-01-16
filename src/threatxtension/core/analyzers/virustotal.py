"""
VirusTotal Analyzer

This module provides threat intelligence integration with VirusTotal API
to check file hashes and identify known malicious extensions.
"""

import os
import hashlib
import logging
import json
from pathlib import Path
from typing import Dict, Optional, List, Any
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Check if vt-py is available
try:
    import vt

    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    logger.warning("vt-py not installed. VirusTotal analysis will be disabled.")

from threatxtension.core.analyzers import BaseAnalyzer


class VirusTotalAnalyzer(BaseAnalyzer):
    """
    Analyzes Chrome extensions using VirusTotal threat intelligence.

    Computes file hashes (SHA256, SHA1, MD5) and checks them against
    VirusTotal's database to identify known malicious files.
    """

    # Priority files to scan (most likely to contain malicious code)
    PRIORITY_FILES = [
        "background.js",
        "content.js",
        "service_worker.js",
        "inject.js",
        "main.js",
        "popup.js",
    ]

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {".js", ".html", ".json"}

    def __init__(self):
        """Initialize the VirusTotalAnalyzer."""
        super().__init__(name="VirusTotalAnalyzer")
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.enabled = bool(self.api_key) and VT_AVAILABLE
        self.config = self._load_config()

        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set. VirusTotal analysis will be disabled.")
        elif not VT_AVAILABLE:
            logger.warning("vt-py library not available. VirusTotal analysis will be disabled.")

    @staticmethod
    def _load_config() -> Dict:
        """Load VirusTotal configuration from JSON file."""
        config_path = Path(__file__).parent.parent.parent / "config" / "virustotal_config.json"
        default_config = {
            "enabled": True,
            "max_files_to_scan": 10,
            "scan_manifest": True,
            "scan_js_files": True,
            "timeout_seconds": 30,
        }
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return {**default_config, **json.load(f)}
        except FileNotFoundError:
            logger.info("VirusTotal config not found, using defaults")
            return default_config
        except json.JSONDecodeError as exc:
            logger.error("Error parsing VirusTotal config: %s", exc)
            return default_config

    @staticmethod
    def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
        """
        Compute hash of a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (sha256, sha1, md5)

        Returns:
            Hex digest of the file hash
        """
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    @staticmethod
    def compute_all_hashes(file_path: str) -> Dict[str, str]:
        """
        Compute SHA256, SHA1, and MD5 hashes of a file.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with hash values
        """
        return {
            "sha256": VirusTotalAnalyzer.compute_file_hash(file_path, "sha256"),
            "sha1": VirusTotalAnalyzer.compute_file_hash(file_path, "sha1"),
            "md5": VirusTotalAnalyzer.compute_file_hash(file_path, "md5"),
        }

    def _get_files_to_scan(self, extension_dir: str) -> List[Dict[str, Any]]:
        """
        Get list of files to scan, prioritizing important files.

        Args:
            extension_dir: Path to the extracted extension directory

        Returns:
            List of file info dicts with path and priority
        """
        files_to_scan = []
        extension_path = Path(extension_dir)

        # First, add priority files if they exist
        for priority_file in self.PRIORITY_FILES:
            for file_path in extension_path.rglob(priority_file):
                if file_path.is_file():
                    files_to_scan.append(
                        {"path": str(file_path), "name": file_path.name, "priority": True}
                    )

        # Then add other scannable files
        for ext in self.SCANNABLE_EXTENSIONS:
            for file_path in extension_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    file_info = {"path": str(file_path), "name": file_path.name, "priority": False}
                    # Avoid duplicates
                    if not any(f["path"] == file_info["path"] for f in files_to_scan):
                        files_to_scan.append(file_info)

        # Limit to max files
        max_files = self.config.get("max_files_to_scan", 10)
        return files_to_scan[:max_files]

    async def _check_hash_virustotal(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Check a file hash against VirusTotal.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            VirusTotal analysis results or None if not found
        """
        if not self.enabled:
            return None

        try:
            async with vt.Client(self.api_key) as client:
                file_report = await client.get_object_async(f"/files/{file_hash}")

                # Extract relevant information
                stats = file_report.last_analysis_stats
                results = {
                    "found": True,
                    "sha256": file_report.sha256,
                    "sha1": getattr(file_report, "sha1", None),
                    "md5": getattr(file_report, "md5", None),
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "total_engines": sum(stats.values()),
                    },
                    "reputation": getattr(file_report, "reputation", 0),
                    "times_submitted": getattr(file_report, "times_submitted", 0),
                    "first_submission_date": str(
                        getattr(file_report, "first_submission_date", "Unknown")
                    ),
                    "last_analysis_date": str(
                        getattr(file_report, "last_analysis_date", "Unknown")
                    ),
                    "type_description": getattr(file_report, "type_description", "Unknown"),
                    "tags": getattr(file_report, "tags", []),
                }

                # Extract malware family names from detections
                if hasattr(file_report, "last_analysis_results"):
                    malware_families = set()
                    for engine, result in file_report.last_analysis_results.items():
                        if result.get("category") in ["malicious", "suspicious"]:
                            result_name = result.get("result", "")
                            if result_name:
                                malware_families.add(result_name)
                    results["malware_families"] = list(malware_families)[:10]
                else:
                    results["malware_families"] = []

                return results

        except vt.error.APIError as e:
            if "NotFoundError" in str(type(e).__name__) or "not found" in str(e).lower():
                return {"found": False, "message": "Hash not found in VirusTotal database"}
            logger.error("VirusTotal API error: %s", e)
            return {"found": False, "error": str(e)}
        except Exception as e:
            logger.error("Error checking VirusTotal: %s", e)
            return {"found": False, "error": str(e)}

    def _check_hash_virustotal_sync(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Synchronous version of VirusTotal hash check.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            VirusTotal analysis results or None if not found
        """
        if not self.enabled:
            return None

        try:
            with vt.Client(self.api_key) as client:
                file_report = client.get_object(f"/files/{file_hash}")

                # Extract relevant information
                stats = file_report.last_analysis_stats
                results = {
                    "found": True,
                    "sha256": file_report.sha256,
                    "sha1": getattr(file_report, "sha1", None),
                    "md5": getattr(file_report, "md5", None),
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "total_engines": sum(stats.values()),
                    },
                    "reputation": getattr(file_report, "reputation", 0),
                    "times_submitted": getattr(file_report, "times_submitted", 0),
                    "first_submission_date": str(
                        getattr(file_report, "first_submission_date", "Unknown")
                    ),
                    "last_analysis_date": str(
                        getattr(file_report, "last_analysis_date", "Unknown")
                    ),
                    "type_description": getattr(file_report, "type_description", "Unknown"),
                    "tags": getattr(file_report, "tags", []),
                }

                # Extract malware family names from detections
                if hasattr(file_report, "last_analysis_results"):
                    malware_families = set()
                    for engine, result in file_report.last_analysis_results.items():
                        if result.get("category") in ["malicious", "suspicious"]:
                            result_name = result.get("result", "")
                            if result_name:
                                malware_families.add(result_name)
                    results["malware_families"] = list(malware_families)[:10]
                else:
                    results["malware_families"] = []

                return results

        except Exception as e:
            error_str = str(e).lower()
            if "not found" in error_str or "404" in error_str:
                return {"found": False, "message": "Hash not found in VirusTotal database"}
            logger.error("VirusTotal API error: %s", e)
            return {"found": False, "error": str(e)}

    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Analyze Chrome extension files using VirusTotal.

        Args:
            extension_dir: Path to the extracted extension directory
            manifest: Parsed manifest.json (optional)
            metadata: Additional metadata about the extension (optional)

        Returns:
            Analysis results with VirusTotal findings
        """
        if not self.enabled:
            return {
                "enabled": False,
                "message": "VirusTotal analysis disabled (API key not configured or vt-py not installed)",
                "files_analyzed": 0,
                "detections": [],
            }

        results = {
            "enabled": True,
            "files_analyzed": 0,
            "files_with_detections": 0,
            "total_malicious": 0,
            "total_suspicious": 0,
            "file_results": [],
            "summary": {
                "threat_level": "clean",
                "detected_families": [],
                "recommendation": "",
            },
        }

        files_to_scan = self._get_files_to_scan(extension_dir)
        logger.info("VirusTotal: Scanning %d files", len(files_to_scan))

        for file_info in files_to_scan:
            try:
                file_path = file_info["path"]
                hashes = self.compute_all_hashes(file_path)

                # Check hash against VirusTotal
                vt_result = self._check_hash_virustotal_sync(hashes["sha256"])

                file_result = {
                    "file_name": file_info["name"],
                    "file_path": file_path.replace(extension_dir, ""),
                    "priority_file": file_info["priority"],
                    "hashes": hashes,
                    "virustotal": vt_result,
                }

                results["file_results"].append(file_result)
                results["files_analyzed"] += 1

                # Track detections
                if vt_result and vt_result.get("found"):
                    stats = vt_result.get("detection_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    if malicious > 0 or suspicious > 0:
                        results["files_with_detections"] += 1
                        results["total_malicious"] += malicious
                        results["total_suspicious"] += suspicious

                        # Collect malware families
                        families = vt_result.get("malware_families", [])
                        results["summary"]["detected_families"].extend(families)

            except Exception as e:
                logger.error("Error analyzing file %s: %s", file_info["path"], e)
                results["file_results"].append(
                    {
                        "file_name": file_info["name"],
                        "error": str(e),
                    }
                )

        # Deduplicate malware families
        results["summary"]["detected_families"] = list(
            set(results["summary"]["detected_families"])
        )[:15]

        # Determine overall threat level
        if results["total_malicious"] > 0:
            results["summary"]["threat_level"] = "malicious"
            results["summary"]["recommendation"] = (
                "HIGH RISK: Multiple antivirus engines have flagged files in this extension as malicious. "
                "Do not install this extension."
            )
        elif results["total_suspicious"] > 0:
            results["summary"]["threat_level"] = "suspicious"
            results["summary"]["recommendation"] = (
                "CAUTION: Some files in this extension have been flagged as suspicious. "
                "Review carefully before installation."
            )
        elif results["files_analyzed"] > 0:
            results["summary"]["threat_level"] = "clean"
            results["summary"]["recommendation"] = (
                "No known threats detected in VirusTotal database. "
                "Note: This does not guarantee the extension is safe."
            )

        return results

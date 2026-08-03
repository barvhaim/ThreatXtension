"""
Entropy Analyzer

This module provides entropy analysis to detect obfuscated/packed JavaScript code.
High entropy values often indicate encrypted, compressed, or heavily obfuscated content.
"""

import os
import re
import math
import logging
from pathlib import Path
from typing import Dict, Optional, List, Any
from collections import Counter

from threatxtension.core.analyzers import BaseAnalyzer

logger = logging.getLogger(__name__)


class EntropyAnalyzer(BaseAnalyzer):
    """
    Analyzes JavaScript files for obfuscation using entropy analysis.

    Shannon entropy measures the randomness/unpredictability of data.
    Normal JavaScript typically has entropy between 4.0-5.5.
    Obfuscated/packed code often has entropy > 7.0.
    """

    ENTROPY_NORMAL_MAX = 5.5
    ENTROPY_SUSPICIOUS_MIN = 6.5
    ENTROPY_HIGH_RISK_MIN = 7.5

    OBFUSCATION_PATTERNS = {
        "eval_usage": {
            "pattern": r"\beval\s*\(",
            "description": "Dynamic code execution via eval()",
            "risk": "high",
        },
        "function_constructor": {
            "pattern": r"\bnew\s+Function\s*\(",
            "description": "Dynamic function creation",
            "risk": "high",
        },
        "hex_strings": {
            "pattern": r"\\x[0-9a-fA-F]{2}",
            "description": "Hex-encoded strings",
            "risk": "medium",
        },
        "unicode_escapes": {
            "pattern": r"\\u[0-9a-fA-F]{4}",
            "description": "Unicode escape sequences",
            "risk": "low",
        },
        "base64_blob": {
            "pattern": r"[A-Za-z0-9+/]{50,}={0,2}",
            "description": "Large Base64-encoded data",
            "risk": "medium",
        },
        "string_array": {
            "pattern": r"\[\s*['\"][^'\"]+['\"]\s*(,\s*['\"][^'\"]+['\"]){10,}\s*\]",
            "description": "Large string array (common in obfuscators)",
            "risk": "medium",
        },
        "jsfuck_pattern": {
            "pattern": r"[\[\]!+]{20,}",
            "description": "JSFuck-style obfuscation",
            "risk": "high",
        },
        "char_code_array": {
            "pattern": r"String\.fromCharCode\s*\([^)]{20,}\)",
            "description": "String building from char codes",
            "risk": "medium",
        },
        "packed_code": {
            "pattern": r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)",
            "description": "Dean Edwards packer signature",
            "risk": "high",
        },
        "obfuscator_io": {
            "pattern": r"_0x[a-f0-9]{4,}",
            "description": "obfuscator.io style variable names",
            "risk": "high",
        },
        "atob_usage": {
            "pattern": r"\batob\s*\(",
            "description": "Base64 decoding (atob)",
            "risk": "low",
        },
        "document_write": {
            "pattern": r"document\.write\s*\(",
            "description": "Dynamic document writing",
            "risk": "medium",
        },
    }

    SKIP_PATTERNS = [
        r"\.min\.js$",
        r"node_modules",
        r"vendor",
        r"lib/",
        r"jquery",
        r"react",
        r"angular",
        r"vue",
        r"bootstrap",
    ]

    def __init__(self):
        """Initialize the EntropyAnalyzer."""
        super().__init__(name="EntropyAnalyzer")

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.

        Args:
            data: Bytes to analyze

        Returns:
            Entropy value (0-8 for bytes)
        """
        if not data:
            return 0.0

        byte_counts = Counter(data)
        total_bytes = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def calculate_string_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            text: String to analyze

        Returns:
            Entropy value
        """
        if not text:
            return 0.0

        char_counts = Counter(text)
        total_chars = len(text)

        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                probability = count / total_chars
                entropy -= probability * math.log2(probability)

        return entropy

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped (libraries, minified, etc.)."""
        file_path_lower = file_path.lower()
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, file_path_lower):
                return True
        return False

    def _detect_obfuscation_patterns(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect common obfuscation patterns in code.

        Args:
            content: JavaScript code content

        Returns:
            List of detected patterns with details
        """
        detected = []

        for pattern_name, pattern_info in self.OBFUSCATION_PATTERNS.items():
            matches = re.findall(pattern_info["pattern"], content)
            if matches:
                detected.append(
                    {
                        "pattern_name": pattern_name,
                        "description": pattern_info["description"],
                        "risk": pattern_info["risk"],
                        "match_count": len(matches),
                        "sample_match": matches[0][:100] if matches else None,
                    }
                )

        return detected

    def _classify_entropy_risk(self, entropy: float) -> str:
        """Classify risk level based on entropy value."""
        if entropy >= self.ENTROPY_HIGH_RISK_MIN:
            return "high"
        elif entropy >= self.ENTROPY_SUSPICIOUS_MIN:
            return "medium"
        elif entropy >= self.ENTROPY_NORMAL_MAX:
            return "low"
        return "normal"

    def _analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a single file for entropy and obfuscation patterns.

        Args:
            file_path: Path to the file

        Returns:
            Analysis results for the file
        """
        try:
            with open(file_path, "rb") as f:
                raw_content = f.read()

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text_content = f.read()

            byte_entropy = self.calculate_shannon_entropy(raw_content)
            char_entropy = self.calculate_string_entropy(text_content)

            # Use byte entropy as primary (more reliable for detecting packed content)
            primary_entropy = byte_entropy

            patterns_detected = self._detect_obfuscation_patterns(text_content)

            high_risk_patterns = [p for p in patterns_detected if p["risk"] == "high"]

            entropy_risk = self._classify_entropy_risk(primary_entropy)

            # Combine entropy and pattern analysis for final risk
            if len(high_risk_patterns) >= 2 or (entropy_risk == "high" and patterns_detected):
                final_risk = "high"
            elif high_risk_patterns or entropy_risk in ["medium", "high"]:
                final_risk = "medium"
            elif patterns_detected or entropy_risk == "low":
                final_risk = "low"
            else:
                final_risk = "normal"

            return {
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "file_size_bytes": len(raw_content),
                "entropy": {
                    "byte_entropy": round(byte_entropy, 2),
                    "char_entropy": round(char_entropy, 2),
                    "risk_level": entropy_risk,
                },
                "obfuscation_patterns": patterns_detected,
                "pattern_count": len(patterns_detected),
                "high_risk_pattern_count": len(high_risk_patterns),
                "overall_risk": final_risk,
                "is_likely_obfuscated": final_risk in ["medium", "high"],
            }

        except Exception as e:
            logger.error("Error analyzing file %s: %s", file_path, e)
            return {
                "file_name": os.path.basename(file_path),
                "file_path": file_path,
                "error": str(e),
                "overall_risk": "unknown",
            }

    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Analyze Chrome extension files for obfuscation.

        Args:
            extension_dir: Path to the extracted extension directory
            manifest: Parsed manifest.json (optional)
            metadata: Additional metadata about the extension (optional)

        Returns:
            Analysis results with entropy and obfuscation findings
        """
        results = {
            "files_analyzed": 0,
            "files_skipped": 0,
            "obfuscated_files": 0,
            "suspicious_files": 0,
            "file_results": [],
            "summary": {
                "overall_risk": "normal",
                "obfuscation_detected": False,
                "high_entropy_files": [],
                "pattern_summary": {},
                "recommendation": "",
            },
        }

        extension_path = Path(extension_dir)

        js_files = list(extension_path.rglob("*.js"))

        logger.info("Entropy analysis: Found %d JavaScript files", len(js_files))

        all_patterns = {}

        for js_file in js_files:
            file_path = str(js_file)

            if self._should_skip_file(file_path):
                results["files_skipped"] += 1
                continue

            file_result = self._analyze_file(file_path)

            # Make path relative for cleaner output
            file_result["file_path"] = file_path.replace(extension_dir, "").lstrip("/\\")

            results["file_results"].append(file_result)
            results["files_analyzed"] += 1

            risk = file_result.get("overall_risk", "normal")
            if risk == "high":
                results["obfuscated_files"] += 1
                results["summary"]["high_entropy_files"].append(
                    {
                        "file": file_result["file_name"],
                        "entropy": file_result.get("entropy", {}).get("byte_entropy", 0),
                        "patterns": len(file_result.get("obfuscation_patterns", [])),
                    }
                )
            elif risk == "medium":
                results["suspicious_files"] += 1

            for pattern in file_result.get("obfuscation_patterns", []):
                pattern_name = pattern["pattern_name"]
                if pattern_name not in all_patterns:
                    all_patterns[pattern_name] = {
                        "description": pattern["description"],
                        "risk": pattern["risk"],
                        "total_occurrences": 0,
                        "files_affected": 0,
                    }
                all_patterns[pattern_name]["total_occurrences"] += pattern["match_count"]
                all_patterns[pattern_name]["files_affected"] += 1

        results["summary"]["pattern_summary"] = all_patterns

        if results["obfuscated_files"] > 0:
            results["summary"]["overall_risk"] = "high"
            results["summary"]["obfuscation_detected"] = True
            results["summary"]["recommendation"] = (
                f"HIGH RISK: {results['obfuscated_files']} file(s) show strong signs of obfuscation. "
                "This may indicate attempts to hide malicious code. Manual review strongly recommended."
            )
        elif results["suspicious_files"] > 0:
            results["summary"]["overall_risk"] = "medium"
            results["summary"]["obfuscation_detected"] = True
            results["summary"]["recommendation"] = (
                f"CAUTION: {results['suspicious_files']} file(s) show suspicious patterns. "
                "While this could be legitimate minification, review is recommended."
            )
        elif results["files_analyzed"] > 0:
            results["summary"]["overall_risk"] = "low"
            results["summary"]["obfuscation_detected"] = False
            results["summary"]["recommendation"] = (
                "No significant obfuscation detected. Code appears to be in readable form."
            )
        else:
            results["summary"]["recommendation"] = "No JavaScript files found to analyze."

        return results

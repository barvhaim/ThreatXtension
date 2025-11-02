"""
Extension Analyzer

This module provides the main analyzer class for Chrome extensions.
"""

from typing import Optional, Dict
from threatxtension.core.analyzers.permissions import PermissionsAnalyzer
from threatxtension.core.analyzers.sast import JavaScriptAnalyzer
from threatxtension.core.analyzers.webstore import WebstoreAnalyzer


class ExtensionAnalyzer:
    """Analyzes Chrome extensions using multiple specialized analyzers."""

    def __init__(
        self,
        extension_dir: str,
        manifest: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ):
        self.extension_dir = extension_dir
        self.manifest = manifest
        self.metadata = metadata
        self.permissions_analyzer = PermissionsAnalyzer()
        self.javascript_analyzer = JavaScriptAnalyzer()
        self.webstore_analyzer = WebstoreAnalyzer()

    def analyze(self) -> Optional[Dict]:
        """
        Analyze the Chrome extension located in the specified directory.
        :return:
        Optional[Dict]: Analysis results including findings and metadata
        """
        permissions_analysis = self.permissions_analyzer.analyze(
            extension_dir=self.extension_dir, manifest=self.manifest
        )

        webstore_analysis = self.webstore_analyzer.analyze(
            extension_dir=self.extension_dir, manifest=self.manifest, metadata=self.metadata
        )

        javascript_analysis = self.javascript_analyzer.analyze(
            extension_dir=self.extension_dir, manifest=self.manifest
        )

        return {
            "permissions_analysis": permissions_analysis,
            "webstore_analysis": webstore_analysis,
            "javascript_analysis": javascript_analysis,
        }

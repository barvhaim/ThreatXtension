"""
Chrome Extension Analyzer Base Classes

This module provides the base classes and common interfaces for analyzing
Chrome extensions for security threats and vulnerabilities.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict


class BaseAnalyzer(ABC):
    """
    Abstract base class for all Chrome extension analyzers.

    Analyzers examine different aspects of Chrome extensions to identify
    security threats, vulnerabilities, and suspicious behavior.
    """

    def __init__(self, name: str):
        """
        Initialize the analyzer.

        Args:
            name: Name of the analyzer
        """
        self.name = name

    @abstractmethod
    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Analyze a Chrome extension.

        Args:
            extension_dir: Path to the extracted extension directory
            manifest: Parsed manifest.json (optional, will be loaded if not provided)
            metadata: Additional metadata about the extension (optional)

        Returns:
            AnalysisResult containing findings and metadata

        Raises:
            Exception: If analysis fails
        """

    def get_name(self) -> str:
        """Get the analyzer name."""
        return self.name

    def __repr__(self) -> str:
        """String representation of the analyzer."""
        return f"{self.__class__.__name__}(name='{self.name}')"

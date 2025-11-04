"""
Chrome Web Store Metadata Analyzer
"""

import os
import logging
from typing import Dict, Optional, List
from datetime import datetime
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse as parse_date
from dotenv import load_dotenv
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from threatxtension.core.analyzers import BaseAnalyzer
from threatxtension.llm.clients import get_chat_llm_client
from threatxtension.llm.prompts import get_prompts

load_dotenv()
logger = logging.getLogger(__name__)


class WebstoreAnalyzer(BaseAnalyzer):
    """Analyzes Chrome Web Store metadata to assess extension reputation risk."""

    def __init__(self):
        """Initialize the WebstoreAnalyzer."""
        super().__init__(name="WebstoreAnalyzer")

    @staticmethod
    def _check_user_engagement_patterns(metadata: Dict) -> List[str]:
        """Check user engagement patterns for suspicious indicators."""
        flags = []

        user_count = metadata.get("user_count")
        rating = metadata.get("rating")
        ratings_count = metadata.get("ratings_count")

        # Convert None to 0 for calculations
        if user_count is None:
            user_count = 0
        if ratings_count is None:
            ratings_count = 0
        if rating is None:
            rating = 0.0

        # Low review ratio (fewer than 1% of users reviewed)
        if user_count > 0 and ratings_count > 0:
            review_ratio = ratings_count / user_count
            if review_ratio < 0.01:
                flags.append(f"Review ratio lower than 1%. ({review_ratio:.4f} < 0.01)")

        # Low user count (< 1,000 users)
        if user_count < 1000:
            flags.append(f"Low user count: {user_count} users (< 1,000)")

        # Low ratings count (< 50 ratings)
        if 0 < ratings_count < 50:
            flags.append(f"Low ratings count: {ratings_count} ratings (< 50)")

        # No ratings at all
        if ratings_count == 0:
            flags.append("No ratings at all")

        # Low average rating (< 3.5)
        if 0 < rating < 3.5:
            flags.append(f"Low average rating: {rating} (< 3.5)")

        return flags

    @staticmethod
    def _check_developer_reputation(metadata: Dict) -> List[str]:
        """Check developer reputation indicators."""
        flags = []

        developer_website = metadata.get("developer_website", "")
        developer_email = metadata.get("developer_email", "")
        developer_name = metadata.get("developer_name", "")

        # Missing developer website
        if not developer_website:
            flags.append("Developer website not provided")

        # Non-professional email domain
        unprofessional_domains = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "protonmail.com",
        ]

        if any(domain in developer_email.lower() for domain in unprofessional_domains):
            flags.append(f"Personal email domain used: {developer_email}")

        # Unusual developer name
        if developer_name and len(developer_name) < 3:
            flags.append(f"Unusually short developer name: {developer_name}")

        # No privacy policy
        if not metadata.get("privacy_policy"):
            flags.append("No privacy policy provided")

        return flags

    @staticmethod
    def _check_update_patterns(metadata: Dict) -> List[str]:
        """Check extension update and age patterns."""
        flags = []

        try:
            last_updated_str = metadata.get("last_updated", "")
            if not last_updated_str:
                return flags

            last_updated = parse_date(last_updated_str, fuzzy=True)
            now = datetime.now()

            # Abandoned: Not updated in over 1 year
            one_year_ago = now - relativedelta(years=1)
            if last_updated < one_year_ago:
                flags.append(
                    f"Abandoned extension: Last updated on {last_updated.date()} (> 1 year ago)"
                )

        except Exception as exc:
            logger.warning("Could not parse update dates: %s", exc)

        return flags

    @staticmethod
    def _check_quality_indicators(metadata: Dict) -> List[str]:
        """Check quality indicators and badges."""
        flags = []

        # Missing best practices badge
        if not metadata.get("follows_best_practices", False):
            flags.append("Not following best practices")

        # Not featured
        if not metadata.get("is_featured", False):
            flags.append("Not featured extension")

        return flags

    def _calculate_suspicion_flags(self, metadata: Dict) -> List[str]:
        """Run heuristic checks and aggregate suspicious flags.

        Args:
            metadata: Extension metadata

        Returns:
            List of all detected suspicious flags
        """
        all_flags = []

        all_flags.extend(self._check_user_engagement_patterns(metadata))
        all_flags.extend(self._check_developer_reputation(metadata))
        all_flags.extend(self._check_quality_indicators(metadata))
        all_flags.extend(self._check_update_patterns(metadata))

        return all_flags

    @staticmethod
    def _llm_analysis_prompt_template(metadata: Dict, red_flags: List[str]) -> PromptTemplate:
        template_str = get_prompts("webstore_analysis")
        template_str = template_str.get("webstore_analysis")

        if not template_str:
            raise NotImplementedError

        template = PromptTemplate(
            input_variables=[
                "extension_name",
                "category",
                "user_count",
                "rating",
                "ratings_count",
                "last_updated",
                "version",
                "developer_name",
                "developer_email",
                "developer_website",
                "follows_best_practices",
                "is_featured",
                "has_privacy_policy",
                "red_flags",
            ],
            template=template_str,
        ).partial(
            extension_name=metadata.get("title", "Unknown"),
            category=metadata.get("category", "Unknown"),
            user_count=str(metadata.get("user_count", "Unknown")),
            rating=str(metadata.get("rating", "Unknown")),
            ratings_count=str(metadata.get("ratings_count", "Unknown")),
            last_updated=metadata.get("last_updated", "Unknown"),
            version=metadata.get("version", "Unknown"),
            developer_name=metadata.get("developer_name", "Unknown"),
            developer_email=metadata.get("developer_email", "Unknown"),
            developer_website=metadata.get("developer_website", "Not provided"),
            follows_best_practices=str(metadata.get("follows_best_practices", False)),
            is_featured=str(metadata.get("is_featured", False)),
            has_privacy_policy=str(bool(metadata.get("privacy_policy"))),
            red_flags="\n -".join(red_flags),
        )
        return template

    @staticmethod
    def _format_analysis_results(analysis_results: Optional[Dict]) -> str:
        """Format the analysis results into a human-readable string."""
        result = "Chrome extension risk assessment based on WebStore reputation analysis:\n"

        if not analysis_results:
            result += " - Unable to perform analysis.\n"
            return result

        risk_summary = analysis_results.get("risk_summary")
        risk_level = analysis_results.get("risk_level")

        if risk_summary and risk_level:
            result += f" - Overall Risk Level: {risk_level}\n"
            result += f" - Summary: {risk_summary}\n"

        else:
            result += " - Incomplete analysis results.\n"

        return result

    def _llm_analysis_risk_assessment(self, metadata: Dict, red_flags: List[str]) -> Optional[str]:
        """Perform LLM-based risk assessment of the extension metadata."""
        model_name = os.getenv("LLM_MODEL", "rits/openai/gpt-oss-20b")
        llm = get_chat_llm_client(
            model_name=model_name,
            model_parameters={
                "temperature": 0.05,
                "max_tokens": 1024,
            },
        )
        prompt = self._llm_analysis_prompt_template(metadata, red_flags)
        chain = prompt | llm | JsonOutputParser()
        llm_analysis = chain.invoke({})
        return self._format_analysis_results(llm_analysis)

    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Analyze Chrome Web Store metadata to assess reputation risk."""
        if metadata is None:
            return None

        logger.info("Analyzing webstore information")

        # Rule-based suspicion flag calculation
        red_flags = self._calculate_suspicion_flags(metadata)
        logger.info("Detected %d suspicious flags", len(red_flags))

        # LLM-based risk assessment
        webstore_analysis = self._llm_analysis_risk_assessment(metadata, red_flags)

        return {
            "webstore_analysis": webstore_analysis,
        }

"""
Summary Generator

Generates executive summaries from all analysis results with overall risk assessment.
"""

import os
import logging
from typing import Dict, Optional
from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from threatxtension.llm.prompts import get_prompts
from threatxtension.llm.clients import get_chat_llm_client
from threatxtension.core.security_scorer import SecurityScorer

load_dotenv()
logger = logging.getLogger(__name__)


class SummaryGenerator:
    """Generates executive summaries from all analysis results."""

    @staticmethod
    def _get_summary_prompt_template(
        analysis_results: Dict,
        manifest: Dict,
    ) -> PromptTemplate:
        """Create prompt template for summary generation."""
        template_str = get_prompts("summary_generation")
        template_str = template_str.get("summary_generation")

        if not template_str:
            raise ValueError("Summary generation prompt template not found")

        extension_name = manifest.get("name", "Unknown Extension")
        extension_description = manifest.get("description", "No description available")
        version = manifest.get("version", "Unknown")

        # Handle None values - use empty dict if None
        permissions_analysis_data = analysis_results.get("permissions_analysis") or {}
        webstore_analysis_data = analysis_results.get("webstore_analysis") or {}
        javascript_analysis_data = analysis_results.get("javascript_analysis") or {}

        permissions_analysis = permissions_analysis_data.get(
            "permissions_analysis", "No analysis available."
        )
        host_permissions_analysis = permissions_analysis_data.get(
            "host_permissions_analysis", "No analysis available."
        )
        webstore_analysis = webstore_analysis_data.get(
            "webstore_analysis", "No analysis available."
        )
        sast_analysis = javascript_analysis_data.get("sast_analysis", "No analysis available.")

        template = PromptTemplate(
            input_variables=[
                "extension_name",
                "extension_description",
                "version",
                "permissions_analysis",
                "host_permissions_analysis",
                "webstore_analysis",
                "sast_analysis",
            ],
            template=template_str,
        ).partial(
            extension_name=extension_name,
            extension_description=extension_description,
            version=version,
            permissions_analysis=permissions_analysis,
            host_permissions_analysis=host_permissions_analysis,
            webstore_analysis=webstore_analysis,
            sast_analysis=sast_analysis,
        )

        return template

    def generate(
        self,
        analysis_results: Dict,
        manifest: Dict,
    ) -> Optional[Dict]:
        """
        Generate executive summary from all analysis results.

        Args:
            analysis_results: Dict containing results from all analyzers
            manifest: Parsed manifest.json data

        Returns:
            Dict with executive summary including:
                - overall_risk_level: "low" | "medium" | "high" | "critical"
                - summary: Executive summary text
                - key_findings: List of critical findings
                - recommendations: List of actionable recommendations
                - security_score: Overall security score (0-100)
                - risk_breakdown: Detailed risk breakdown by category
        """
        if not analysis_results:
            logger.warning("No analysis results provided for summary generation")
            return None

        if not manifest:
            logger.warning("No manifest data provided for summary generation")
            return None

        # Calculate security score using SecurityScorer
        scorer = SecurityScorer()
        score_results = scorer.calculate_score(analysis_results)
        
        logger.info(
            "Security score calculated: %d/100 (Risk: %s)",
            score_results['security_score'],
            score_results['risk_level']
        )

        prompt = self._get_summary_prompt_template(
            analysis_results=analysis_results,
            manifest=manifest,
        )
        model_name = os.getenv("LLM_MODEL", "rits/openai/gpt-oss-120b")
        llm = get_chat_llm_client(
            model_name=model_name,
            model_parameters={
                "temperature": 0.05,
                "max_tokens": 4096,
            },
        )

        try:
            chain = prompt | llm | JsonOutputParser()
            summary = chain.invoke({})
            
            # Add security score to summary
            summary['security_score'] = score_results['security_score']
            summary['overall_risk_level'] = score_results['risk_level']
            summary['risk_breakdown'] = score_results['risk_breakdown']
            summary['risk_details'] = score_results['risk_details']
            summary['total_risk_points'] = score_results['total_risk_points']
            
            logger.info("Executive summary generated successfully with security score")
            return summary
        except Exception as exc:
            logger.exception("Failed to generate executive summary: %s", exc)
            # Return score results even if LLM summary fails
            return {
                'security_score': score_results['security_score'],
                'overall_risk_level': score_results['risk_level'],
                'risk_breakdown': score_results['risk_breakdown'],
                'risk_details': score_results['risk_details'],
                'total_risk_points': score_results['total_risk_points'],
                'summary': f"Security analysis completed with score: {score_results['security_score']}/100",
                'key_findings': [],
                'recommendations': ['Review detailed analysis results for specific findings'],
                'error': str(exc)
            }

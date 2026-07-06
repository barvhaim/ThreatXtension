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
        chromestats_analysis_data = analysis_results.get("chromestats_analysis") or {}

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
        
        # Format chrome-stats analysis for LLM
        chromestats_analysis = "No Chrome Stats analysis available."
        if chromestats_analysis_data.get("enabled"):
            api_risk = chromestats_analysis_data.get("api_risk_analysis", {})
            risk_indicators = chromestats_analysis_data.get("risk_indicators", [])
            overall_risk = chromestats_analysis_data.get("overall_risk_level", "unknown")
            
            if api_risk.get("has_api_risk_data"):
                risk_impact = api_risk.get("risk_impact", 0)
                risk_likelihood = api_risk.get("risk_likelihood", 0)
                chromestats_analysis = f"""Chrome Stats Behavioral Analysis:
- Overall Risk Level: {overall_risk.upper()}
- Risk Impact Score: {risk_impact}/3
- Risk Likelihood Score: {risk_likelihood}/3

Critical Risk Indicators:
{chr(10).join(f"  • {indicator}" for indicator in risk_indicators[:5]) if risk_indicators else "  • None detected"}

This data comes from chrome-stats.com API and includes store removal status, permission risks, and behavioral patterns."""
            elif risk_indicators:
                chromestats_analysis = f"""Chrome Stats Behavioral Analysis:
- Overall Risk Level: {overall_risk.upper()}
- Risk Indicators Detected: {len(risk_indicators)}

Key Indicators:
{chr(10).join(f"  • {indicator}" for indicator in risk_indicators[:5])}"""

        template = PromptTemplate(
            input_variables=[
                "extension_name",
                "extension_description",
                "version",
                "permissions_analysis",
                "host_permissions_analysis",
                "webstore_analysis",
                "sast_analysis",
                "chromestats_analysis",
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
            chromestats_analysis=chromestats_analysis,
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

    def generate_executive_summary(
        self,
        analysis_results: Dict,
        manifest: Dict,
    ) -> Optional[Dict]:
        """
        Generate enhanced executive summary with business impact analysis.

        Args:
            analysis_results: Dict containing results from all analyzers
            manifest: Parsed manifest.json data

        Returns:
            Dict with enhanced executive summary including:
                - executive_overview: C-level summary
                - business_impact: Business consequences analysis
                - risk_quantification: Risk metrics in business terms
                - compliance_implications: Regulatory compliance issues
                - remediation_roi: Cost-benefit analysis
                - action_items: Prioritized actions with timelines
                - executive_recommendations: Strategic recommendations
        """
        if not analysis_results:
            logger.warning("No analysis results provided for executive summary generation")
            return None

        if not manifest:
            logger.warning("No manifest data provided for executive summary generation")
            return None

        # Calculate security score using SecurityScorer
        scorer = SecurityScorer()
        score_results = scorer.calculate_score(analysis_results)
        
        logger.info(
            "Generating executive summary with security score: %d/100 (Risk: %s)",
            score_results['security_score'],
            score_results['risk_level']
        )

        # Get executive summary prompt template
        try:
            template_str = get_prompts("executive_summary")
            template_str = template_str.get("executive_summary")
            
            if not template_str:
                raise ValueError("Executive summary prompt template not found")

            extension_name = manifest.get("name", "Unknown Extension")
            extension_description = manifest.get("description", "No description available")
            version = manifest.get("version", "Unknown")

            # Handle None values - use empty dict if None
            permissions_analysis_data = analysis_results.get("permissions_analysis") or {}
            webstore_analysis_data = analysis_results.get("webstore_analysis") or {}
            javascript_analysis_data = analysis_results.get("javascript_analysis") or {}
            chromestats_analysis_data = analysis_results.get("chromestats_analysis") or {}

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
            
            # Format chrome-stats analysis for LLM
            chromestats_analysis = "No Chrome Stats analysis available."
            if chromestats_analysis_data.get("enabled"):
                api_risk = chromestats_analysis_data.get("api_risk_analysis", {})
                risk_indicators = chromestats_analysis_data.get("risk_indicators", [])
                overall_risk = chromestats_analysis_data.get("overall_risk_level", "unknown")
                
                if api_risk.get("has_api_risk_data"):
                    risk_impact = api_risk.get("risk_impact", 0)
                    risk_likelihood = api_risk.get("risk_likelihood", 0)
                    chromestats_analysis = f"""Chrome Stats Behavioral Analysis:
- Overall Risk Level: {overall_risk.upper()}
- Risk Impact Score: {risk_impact}/3
- Risk Likelihood Score: {risk_likelihood}/3

Critical Risk Indicators:
{chr(10).join(f"  • {indicator}" for indicator in risk_indicators[:5]) if risk_indicators else "  • None detected"}

This data comes from chrome-stats.com API and includes store removal status, permission risks, and behavioral patterns."""
                elif risk_indicators:
                    chromestats_analysis = f"""Chrome Stats Behavioral Analysis:
- Overall Risk Level: {overall_risk.upper()}
- Risk Indicators Detected: {len(risk_indicators)}

Key Indicators:
{chr(10).join(f"  • {indicator}" for indicator in risk_indicators[:5])}"""

            # Format risk breakdown for prompt
            risk_breakdown_str = "\n".join([
                f"- {category}: {details['points']} points ({details['level']})"
                for category, details in score_results['risk_breakdown'].items()
            ])

            template = PromptTemplate(
                input_variables=[
                    "extension_name",
                    "extension_description",
                    "version",
                    "security_score",
                    "risk_level",
                    "total_risk_points",
                    "permissions_analysis",
                    "host_permissions_analysis",
                    "webstore_analysis",
                    "sast_analysis",
                    "chromestats_analysis",
                    "risk_breakdown",
                ],
                template=template_str,
            ).partial(
                extension_name=extension_name,
                extension_description=extension_description,
                version=version,
                security_score=score_results['security_score'],
                risk_level=score_results['risk_level'],
                total_risk_points=score_results['total_risk_points'],
                permissions_analysis=permissions_analysis,
                host_permissions_analysis=host_permissions_analysis,
                webstore_analysis=webstore_analysis,
                sast_analysis=sast_analysis,
                chromestats_analysis=chromestats_analysis,
                risk_breakdown=risk_breakdown_str,
            )

            model_name = os.getenv("LLM_MODEL", "rits/openai/gpt-oss-120b")
            llm = get_chat_llm_client(
                model_name=model_name,
                model_parameters={
                    "temperature": 0.1,
                    "max_tokens": 8192,
                },
            )

            chain = template | llm | JsonOutputParser()
            executive_summary = chain.invoke({})
            
            # Add security score details to summary
            executive_summary['security_score'] = score_results['security_score']
            executive_summary['risk_breakdown'] = score_results['risk_breakdown']
            executive_summary['risk_details'] = score_results['risk_details']
            executive_summary['total_risk_points'] = score_results['total_risk_points']
            
            logger.info("Enhanced executive summary generated successfully")
            return executive_summary
            
        except Exception as exc:
            logger.exception("Failed to generate executive summary: %s", exc)
            # Return basic summary with score results
            return {
                'executive_overview': f"Security analysis completed with score: {score_results['security_score']}/100 (Risk: {score_results['risk_level']})",
                'overall_risk_level': score_results['risk_level'],
                'security_score': score_results['security_score'],
                'risk_breakdown': score_results['risk_breakdown'],
                'risk_details': score_results['risk_details'],
                'total_risk_points': score_results['total_risk_points'],
                'business_impact': {
                    'data_breach_risk': 'Unable to generate detailed analysis',
                    'operational_impact': 'Unable to generate detailed analysis',
                    'reputational_damage': 'Unable to generate detailed analysis',
                    'financial_impact_range': 'Unknown',
                    'user_exposure': 'Unknown'
                },
                'key_findings': [],
                'action_items': [],
                'executive_recommendations': ['Review detailed analysis results for specific findings'],
                'error': str(exc)
            }

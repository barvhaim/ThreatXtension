"""
Chrome Stats Analyzer

This module provides behavioral threat intelligence by analyzing Chrome Web Store
statistics including install trends, rating patterns, developer reputation, and
geographic distribution.
"""

import os
import logging
import requests
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
from dotenv import load_dotenv

from threatxtension.core.analyzers import BaseAnalyzer

load_dotenv()
logger = logging.getLogger(__name__)


class ChromeStatsAnalyzer(BaseAnalyzer):
    """
    Analyzes Chrome extension behavioral patterns using Chrome Stats API.
    
    Detects:
    - Suspicious install/uninstall patterns
    - Rating manipulation
    - Developer reputation issues
    - Geographic anomalies
    - Similar malicious extensions
    """

    NORMAL_UNINSTALL_RATE = 0.10  # 10%
    HIGH_UNINSTALL_RATE = 0.30    # 30%
    SUSPICIOUS_GROWTH_RATE = 5.0   # 500% increase
    MIN_RATING_DROP = 1.0          # 1 star drop
    NEW_DEVELOPER_DAYS = 90        # 3 months
    HIGH_RISK_REGIONS = {'RU', 'CN', 'Unknown'}  # ISO country codes

    def __init__(self):
        """Initialize the ChromeStatsAnalyzer."""
        super().__init__(name="ChromeStatsAnalyzer")
        self.api_key = os.getenv("CHROMESTATS_API_KEY")
        self.api_base_url = os.getenv("CHROMESTATS_API_URL", "https://chrome-stats.com")
        self.enabled = bool(self.api_key)
        
        if not self.api_key:
            logger.warning("CHROMESTATS_API_KEY not set. Chrome Stats analysis will be disabled.")

    def _make_api_request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make request to Chrome Stats API.
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            
        Returns:
            API response data or None on error
        """
        if not self.enabled:
            return None
            
        try:
            url = f"{self.api_base_url}/{endpoint}"
            
            if params is None:
                params = {}
            
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": self.api_key  # Try API key in header
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error("Chrome Stats API error: %s", e)
            return None
        except Exception as e:
            logger.error("Error making Chrome Stats request: %s", e)
            return None

    def _analyze_install_trends(self, stats_data: Dict) -> Dict[str, Any]:
        """
        Analyze install/uninstall patterns for suspicious behavior.
        
        Args:
            stats_data: Stats data from API
            
        Returns:
            Analysis results with risk indicators
        """
        trends = stats_data.get('install_trends', {})
        current_installs = trends.get('daily_installs', 0)
        previous_installs = trends.get('previous_daily_installs', 0)
        uninstall_rate = trends.get('uninstall_rate', 0)
        net_growth = trends.get('net_growth', 0)
        
        risk_indicators = []
        risk_score = 0
        
        if previous_installs > 0:
            growth_rate = (current_installs - previous_installs) / previous_installs
            if growth_rate > self.SUSPICIOUS_GROWTH_RATE:
                risk_indicators.append(f"Suspicious install spike: {growth_rate*100:.0f}% increase")
                risk_score += 5
        
        if uninstall_rate > self.HIGH_UNINSTALL_RATE:
            risk_indicators.append(f"High uninstall rate: {uninstall_rate*100:.0f}% (normal: <10%)")
            risk_score += 3
        elif uninstall_rate > self.NORMAL_UNINSTALL_RATE:
            risk_indicators.append(f"Elevated uninstall rate: {uninstall_rate*100:.0f}%")
            risk_score += 1
        
        if net_growth < 0:
            risk_indicators.append(f"Declining user base: {net_growth} users")
            risk_score += 2
        
        return {
            'daily_installs': current_installs,
            'previous_daily_installs': previous_installs,
            'uninstall_rate': uninstall_rate,
            'net_growth': net_growth,
            'risk_indicators': risk_indicators,
            'risk_score': min(5, risk_score),
            'risk_level': 'high' if risk_score >= 5 else 'medium' if risk_score >= 3 else 'low'
        }

    def _analyze_rating_patterns(self, rating_data: Dict) -> Dict[str, Any]:
        """
        Analyze rating changes for manipulation or quality issues.
        
        Args:
            rating_data: Rating history from API
            
        Returns:
            Analysis results with anomalies
        """
        current_rating = rating_data.get('current_rating', 0)
        previous_rating = rating_data.get('rating_30_days_ago', 0)
        recent_reviews = rating_data.get('recent_reviews', [])
        fake_review_probability = rating_data.get('fake_review_probability', 0)
        
        risk_indicators = []
        risk_score = 0
        
        if previous_rating > 0:
            rating_drop = previous_rating - current_rating
            if rating_drop >= self.MIN_RATING_DROP:
                risk_indicators.append(f"Major rating drop: {previous_rating:.1f} → {current_rating:.1f}")
                risk_score += 3
        
        if current_rating < 3.0:
            risk_indicators.append(f"Low rating: {current_rating:.1f}/5.0")
            risk_score += 2
        
        if fake_review_probability > 0.5:
            risk_indicators.append(f"High fake review probability: {fake_review_probability*100:.0f}%")
            risk_score += 2
        
        negative_count = sum(1 for r in recent_reviews if r.get('rating', 5) <= 2)
        if recent_reviews and negative_count / len(recent_reviews) > 0.7:
            risk_indicators.append(f"Mostly negative recent reviews: {negative_count}/{len(recent_reviews)}")
            risk_score += 2
        
        return {
            'current_rating': current_rating,
            'previous_rating': previous_rating,
            'rating_change': previous_rating - current_rating if previous_rating > 0 else 0,
            'fake_review_probability': fake_review_probability,
            'recent_negative_percentage': negative_count / len(recent_reviews) if recent_reviews else 0,
            'risk_indicators': risk_indicators,
            'risk_score': min(5, risk_score),
            'risk_level': 'high' if risk_score >= 4 else 'medium' if risk_score >= 2 else 'low'
        }

    def _analyze_developer_reputation(self, developer_data: Dict) -> Dict[str, Any]:
        """
        Analyze developer history and reputation.
        
        Args:
            developer_data: Developer information from API
            
        Returns:
            Reputation analysis with trust score
        """
        account_age_days = developer_data.get('account_age_days', 0)
        total_extensions = developer_data.get('total_extensions', 0)
        removed_extensions = developer_data.get('removed_extensions', 0)
        policy_violations = developer_data.get('policy_violations', [])
        
        risk_indicators = []
        risk_score = 0
        
        if account_age_days < self.NEW_DEVELOPER_DAYS:
            risk_indicators.append(f"New developer account: {account_age_days} days old")
            risk_score += 2
        
        if removed_extensions > 0:
            risk_indicators.append(f"{removed_extensions} extensions removed for violations")
            risk_score += 5
        
        if policy_violations:
            violation_types = [v.get('type', 'Unknown') for v in policy_violations]
            risk_indicators.append(f"Policy violations: {', '.join(violation_types)}")
            risk_score += len(policy_violations) * 2
        
        # Calculate trust score (0-100, inverted from risk)
        trust_score = max(0, 100 - (risk_score * 10))
        
        return {
            'account_age_days': account_age_days,
            'total_extensions': total_extensions,
            'removed_extensions': removed_extensions,
            'policy_violations': policy_violations,
            'trust_score': trust_score,
            'risk_indicators': risk_indicators,
            'risk_score': min(10, risk_score),
            'risk_level': 'high' if risk_score >= 7 else 'medium' if risk_score >= 4 else 'low'
        }

    def _analyze_geographic_distribution(self, geo_data: Dict) -> Dict[str, Any]:
        """
        Analyze geographic distribution for anomalies.
        
        Args:
            geo_data: Geographic distribution data
            
        Returns:
            Geographic analysis with anomalies
        """
        country_distribution = geo_data.get('country_distribution', {})
        
        risk_indicators = []
        risk_score = 0
        
        total_installs = sum(country_distribution.values())
        high_risk_installs = sum(
            count for country, count in country_distribution.items()
            if country in self.HIGH_RISK_REGIONS
        )
        
        if total_installs > 0:
            high_risk_percentage = high_risk_installs / total_installs
            
            if high_risk_percentage > 0.7:
                risk_indicators.append(f"{high_risk_percentage*100:.0f}% installs from high-risk regions")
                risk_score += 3
            elif high_risk_percentage > 0.5:
                risk_indicators.append(f"{high_risk_percentage*100:.0f}% installs from high-risk regions")
                risk_score += 2
        
        if country_distribution:
            top_country_percentage = max(country_distribution.values()) / total_installs if total_installs > 0 else 0
            if top_country_percentage > 0.8:
                risk_indicators.append(f"Unusual geographic concentration: {top_country_percentage*100:.0f}% from one country")
                risk_score += 1
        
        return {
            'country_distribution': country_distribution,
            'high_risk_percentage': high_risk_installs / total_installs if total_installs > 0 else 0,
            'top_countries': sorted(country_distribution.items(), key=lambda x: x[1], reverse=True)[:5],
            'risk_indicators': risk_indicators,
            'risk_score': min(3, risk_score),
            'risk_level': 'high' if risk_score >= 3 else 'medium' if risk_score >= 2 else 'low'
        }

    def _analyze_similar_extensions(self, similar_data: Dict) -> Dict[str, Any]:
        """
        Analyze similar extensions for clone networks or impersonation.
        
        Args:
            similar_data: Similar extensions data
            
        Returns:
            Analysis of similar extensions
        """
        similar_extensions = similar_data.get('similar_extensions', [])
        removed_similar = [ext for ext in similar_extensions if ext.get('removed', False)]
        same_developer = [ext for ext in similar_extensions if ext.get('same_developer', False)]
        
        risk_indicators = []
        risk_score = 0
        
        if removed_similar:
            risk_indicators.append(f"{len(removed_similar)} similar extensions removed for violations")
            risk_score += 5
        
        if len(same_developer) > 3:
            risk_indicators.append(f"Developer has {len(same_developer)} similar extensions")
            risk_score += 2
        
        return {
            'similar_count': len(similar_extensions),
            'removed_similar': len(removed_similar),
            'same_developer_count': len(same_developer),
            'risk_indicators': risk_indicators,
            'risk_score': min(5, risk_score),
            'risk_level': 'high' if risk_score >= 5 else 'medium' if risk_score >= 3 else 'low'
        }

    def _analyze_api_risk_data(self, extension_data: Dict) -> Dict[str, Any]:
        """
        Analyze risk data provided directly by chrome-stats.com API.
        
        This includes riskImpact and riskLikelihood scores with detailed reasons.
        
        Args:
            extension_data: Extension data from API
            
        Returns:
            Analysis of API-provided risk data
        """
        risk_data = extension_data.get('risk', {})
        
        if not risk_data:
            return {
                'has_api_risk_data': False,
                'risk_score': 0,
                'risk_indicators': [],
                'risk_level': 'low'
            }
        
        risk_impact = risk_data.get('riskImpact', 0)
        risk_likelihood = risk_data.get('riskLikelihood', 0)
        impact_reasons = risk_data.get('riskImpactReasons', [])
        likelihood_reasons = risk_data.get('riskLikelihoodReasons', [])
        
        risk_indicators = []
        risk_score = 0
        
        # Process impact reasons (what the extension CAN do)
        for reason in impact_reasons:
            reason_text = reason.get('reason', '')
            severity = reason.get('severity', 'Low')
            description = reason.get('description', '')
            reason_risk = reason.get('risk', 0)
            
            risk_indicators.append(f"[{severity}] {description}")

            if severity == 'Critical':
                risk_score += min(10, reason_risk // 2)  # Scale down API risk to our scoring
            elif severity == 'High':
                risk_score += min(5, reason_risk // 3)
            elif severity == 'Medium':
                risk_score += min(3, reason_risk // 5)
        
        # Process likelihood reasons (behavioral indicators of malicious intent)
        for reason in likelihood_reasons:
            reason_text = reason.get('reason', '')
            severity = reason.get('severity', 'Low')
            description = reason.get('description', '')
            reason_risk = reason.get('risk', 0)
            
            # Likelihood reasons are MORE important for security scoring
            risk_indicators.append(f"[{severity}] {description}")
            
            if reason_text == 'removed-from-store':
                risk_score += 15  # CRITICAL: Extension was removed from store
            elif severity == 'Critical':
                risk_score += min(12, abs(reason_risk) * 2)
            elif severity == 'High':
                risk_score += min(8, abs(reason_risk) * 2)
            elif severity == 'Medium':
                risk_score += min(4, abs(reason_risk))
        
        if risk_score >= 15 or risk_likelihood >= 3:
            risk_level = 'critical'
        elif risk_score >= 10 or risk_likelihood >= 2:
            risk_level = 'high'
        elif risk_score >= 5 or risk_likelihood >= 1:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'has_api_risk_data': True,
            'risk_impact': risk_impact,
            'risk_likelihood': risk_likelihood,
            'impact_reasons_count': len(impact_reasons),
            'likelihood_reasons_count': len(likelihood_reasons),
            'risk_indicators': risk_indicators,
            'risk_score': min(20, risk_score),  # Cap at 20 points for API risk data
            'risk_level': risk_level
        }

    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Analyze Chrome extension using Chrome Stats API.
        
        Args:
            extension_dir: Path to the extracted extension directory
            manifest: Parsed manifest.json (optional)
            metadata: Additional metadata including extension_id (required)
            
        Returns:
            Analysis results with behavioral threat intelligence
        """
        if not self.enabled:
            return {
                'enabled': False,
                'message': 'Chrome Stats analysis disabled (API key not configured)',
            }
        
        if not metadata or 'extension_id' not in metadata:
            logger.warning("Extension ID not provided, cannot perform Chrome Stats analysis")
            return {
                'enabled': True,
                'error': 'Extension ID required for Chrome Stats analysis',
            }
        
        extension_id = metadata['extension_id']
        logger.info("Chrome Stats: Analyzing extension %s", extension_id)
        
        # API endpoint: /api/detail?id={extension_id}
        extension_data = self._make_api_request("api/detail", params={'id': extension_id})
        
        if not extension_data:
            return {
                'enabled': True,
                'error': 'Failed to fetch Chrome Stats data',
            }
        
        api_risk_analysis = self._analyze_api_risk_data(extension_data)

        # All behavioral analyses read the same single API response
        install_analysis = self._analyze_install_trends(extension_data)
        rating_analysis = self._analyze_rating_patterns(extension_data)
        developer_analysis = self._analyze_developer_reputation(extension_data)
        geo_analysis = self._analyze_geographic_distribution(extension_data)
        similar_analysis = self._analyze_similar_extensions(extension_data)
        
        total_risk_score = (
            api_risk_analysis['risk_score'] +  # max 20 points
            install_analysis['risk_score'] +
            rating_analysis['risk_score'] +
            developer_analysis['risk_score'] +
            geo_analysis['risk_score'] +
            similar_analysis['risk_score']
        )
        
        all_risk_indicators = (
            api_risk_analysis['risk_indicators'] +
            install_analysis['risk_indicators'] +
            rating_analysis['risk_indicators'] +
            developer_analysis['risk_indicators'] +
            geo_analysis['risk_indicators'] +
            similar_analysis['risk_indicators']
        )
        
        if total_risk_score >= 20 or api_risk_analysis['risk_level'] == 'critical':
            overall_risk = 'critical'
        elif total_risk_score >= 15:
            overall_risk = 'high'
        elif total_risk_score >= 8:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'enabled': True,
            'extension_id': extension_id,
            'overall_risk_level': overall_risk,
            'total_risk_score': total_risk_score,
            'risk_indicators': all_risk_indicators,
            'api_risk_analysis': api_risk_analysis,
            'install_trends': install_analysis,
            'rating_patterns': rating_analysis,
            'developer_reputation': developer_analysis,
            'geographic_distribution': geo_analysis,
            'similar_extensions': similar_analysis,
            'analyzed_at': datetime.utcnow().isoformat(),
        }

# Made with Bob

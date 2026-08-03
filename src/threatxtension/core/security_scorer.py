"""
Security Scorer

Calculates overall risk score from all analyzer results.
Aggregates risk points from SAST, permissions, VirusTotal, entropy, webstore, and manifest.
"""

import logging
from typing import Dict, Optional, List, Any

logger = logging.getLogger(__name__)


class SecurityScorer:
    """
    Calculates overall risk score from all analyzer results.

    Score: 0-100 where higher means more dangerous:
    - 0-15:   Low risk (green)      — no meaningful signals detected
    - 16-35:  Medium risk (yellow)  — some concerns, needs review
    - 36-60:  High risk (orange)    — significant suspicious signals
    - 61-100: Critical risk (red)   — confirmed malicious indicators

    Thresholds are intentionally tight because VT and SAST may both be
    absent (disabled / no JS files), so the remaining analyzers alone must
    be able to push borderline extensions out of the "Low" band.

    Risk points are accumulated from the analyzers and capped at 100.
    """

    # Category maxima deliberately sum to >100 so a single strong signal (e.g. one
    # VirusTotal hit) can reach the danger zone on its own.
    WEIGHTS = {
        'sast': 60,
        'permissions': 30,
        'virustotal': 50,
        'entropy': 30,
        'chromestats': 28,
        'webstore': 5,
        'manifest': 5,
    }

    HIGH_RISK_PERMISSIONS = {
        'debugger', 'webRequest', 'webRequestBlocking', 'cookies',
        'clipboardRead', 'nativeMessaging', 'proxy', 'management',
        'desktopCapture', 'tabCapture', 'browsingData', 'history'
    }

    def __init__(self):
        """Initialize the SecurityScorer."""
        self.name = "SecurityScorer"

    def calculate_score(self, analysis_results: Dict) -> Dict[str, Any]:
        """
        Calculate security score from all analysis results.

        Args:
            analysis_results: Dictionary containing results from all analyzers

        Returns:
            Dictionary with security_score, risk_level, and detailed breakdown
        """
        risk_points = 0
        breakdown = {}
        details = {}

        sast_risk, sast_details = self._calculate_sast_risk(
            analysis_results.get('javascript_analysis', {})
        )
        risk_points += sast_risk
        breakdown['sast'] = sast_risk
        details['sast'] = sast_details

        perm_risk, perm_details = self._calculate_permissions_risk(
            analysis_results.get('permissions_analysis', {})
        )
        risk_points += perm_risk
        breakdown['permissions'] = perm_risk
        details['permissions'] = perm_details

        vt_risk, vt_details = self._calculate_virustotal_risk(
            analysis_results.get('virustotal_analysis', {})
        )
        risk_points += vt_risk
        breakdown['virustotal'] = vt_risk
        details['virustotal'] = vt_details

        entropy_risk, entropy_details = self._calculate_entropy_risk(
            analysis_results.get('entropy_analysis', {})
        )
        risk_points += entropy_risk
        breakdown['entropy'] = entropy_risk
        details['entropy'] = entropy_details

        chromestats_risk, chromestats_details = self._calculate_chromestats_risk(
            analysis_results.get('chromestats_analysis', {})
        )
        risk_points += chromestats_risk
        breakdown['chromestats'] = chromestats_risk
        details['chromestats'] = chromestats_details

        webstore_risk, webstore_details = self._calculate_webstore_risk(
            analysis_results.get('webstore_analysis', {})
        )
        risk_points += webstore_risk
        breakdown['webstore'] = webstore_risk
        details['webstore'] = webstore_details

        manifest_risk, manifest_details = self._calculate_manifest_risk(
            analysis_results.get('manifest', {})
        )
        risk_points += manifest_risk
        breakdown['manifest'] = manifest_risk
        details['manifest'] = manifest_details

        # Cap at 100. Higher means more dangerous.
        total_risk = min(100, risk_points)
        security_score = total_risk

        risk_level = self._get_risk_level(security_score)

        logger.info(
            "Risk score calculated: %d/100 (Risk: %s, Total risk points: %d)",
            security_score, risk_level, total_risk
        )

        return {
            'security_score': security_score,
            'risk_level': risk_level,
            'total_risk_points': total_risk,
            'risk_breakdown': breakdown,
            'risk_details': details,
            'max_possible_risk': sum(self.WEIGHTS.values()),
        }

    def _calculate_sast_risk(self, sast_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from SAST findings (max 60 points).

        Args:
            sast_data: SAST analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        findings = sast_data.get('sast_findings', {})
        if not findings:
            return 0, {'message': 'No SAST findings'}

        risk = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for file_findings in findings.values():
            for finding in file_findings:
                severity = finding.get('extra', {}).get('severity', 'INFO')
                if severity == 'CRITICAL':
                    risk += 15
                    critical_count += 1
                elif severity == 'ERROR':
                    risk += 12
                    high_count += 1
                elif severity == 'WARNING':
                    risk += 5
                    medium_count += 1
                elif severity == 'INFO':
                    risk += 1
                    low_count += 1

        bonus = 0
        if critical_count >= 10:
            bonus = 30
            risk += bonus
        elif critical_count >= 5:
            bonus = 15
            risk += bonus

        details = {
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'total': critical_count + high_count + medium_count + low_count,
            'bonus_penalty': bonus,
            'message': f'{critical_count} critical, {high_count} high, {medium_count} medium findings'
        }

        return min(60, risk), details

    def _calculate_permissions_risk(self, perm_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from permissions (max 30 points).

        Args:
            perm_data: Permissions analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        details_dict = perm_data.get('permissions_details', {})
        if not details_dict:
            return 0, {'message': 'No permissions data'}

        risk = 0
        unreasonable_count = 0
        high_risk_count = 0
        unreasonable_perms = []

        for perm_name, perm_info in details_dict.items():
            if not perm_info.get('is_reasonable', True):
                unreasonable_count += 1
                unreasonable_perms.append(perm_name)
                
                if perm_name in self.HIGH_RISK_PERMISSIONS:
                    risk += 10
                    high_risk_count += 1
                else:
                    risk += 5

        host_analysis = perm_data.get('host_permissions_analysis', '')
        critical_host = False
        if '<all_urls>' in host_analysis or '*://*/*' in host_analysis:
            risk += 15  # Critical host permission
            critical_host = True

        bonus = 0
        if unreasonable_count >= 10:
            bonus = 20
            risk += bonus
        elif unreasonable_count >= 5:
            bonus = 10
            risk += bonus

        details = {
            'unreasonable_count': unreasonable_count,
            'high_risk_count': high_risk_count,
            'critical_host_permission': critical_host,
            'bonus_penalty': bonus,
            'unreasonable_permissions': unreasonable_perms[:10],  # Limit to 10 for display
            'message': f'{unreasonable_count} unreasonable permissions ({high_risk_count} high-risk)'
        }

        return min(30, risk), details

    def _calculate_virustotal_risk(self, vt_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from VirusTotal (max 50 points).

        Args:
            vt_data: VirusTotal analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        if not vt_data.get('enabled'):
            return 0, {'message': 'VirusTotal not enabled'}

        threat_level = vt_data.get('summary', {}).get('threat_level', 'clean')
        malicious = vt_data.get('total_malicious', 0)
        suspicious = vt_data.get('total_suspicious', 0)
        files_analyzed = vt_data.get('files_analyzed', 0)
        families = vt_data.get('summary', {}).get('detected_families', [])

        risk = 0
        if threat_level == 'malicious' or malicious > 0:
            risk = 50  # Instant high risk
        elif threat_level == 'suspicious' or suspicious > 0:
            risk = 25

        details = {
            'threat_level': threat_level,
            'malicious_detections': malicious,
            'suspicious_detections': suspicious,
            'files_analyzed': files_analyzed,
            'malware_families': families[:5],  # Limit to 5 for display
            'message': f'Threat level: {threat_level} ({malicious} malicious, {suspicious} suspicious)'
        }

        return risk, details

    def _calculate_entropy_risk(self, entropy_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from entropy/obfuscation (max 30 points).

        Args:
            entropy_data: Entropy analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        if not entropy_data:
            return 0, {'message': 'No entropy analysis'}

        risk = 0
        overall_risk = entropy_data.get('summary', {}).get('overall_risk', 'normal')
        obfuscated = entropy_data.get('obfuscated_files', 0)
        suspicious = entropy_data.get('suspicious_files', 0)
        files_analyzed = entropy_data.get('files_analyzed', 0)

        if obfuscated > 0:
            risk += min(20, obfuscated * 10)  # 10 points per obfuscated file, max 20

        if suspicious > 0:
            risk += min(10, suspicious * 5)   # 5 points per suspicious file, max 10

        patterns = entropy_data.get('summary', {}).get('pattern_summary', {})
        high_risk_patterns = [p for p, info in patterns.items()
                             if info.get('risk') == 'high']
        pattern_bonus = 0
        if len(high_risk_patterns) >= 3:
            pattern_bonus = 10
            risk += pattern_bonus

        details = {
            'overall_risk': overall_risk,
            'obfuscated_files': obfuscated,
            'suspicious_files': suspicious,
            'files_analyzed': files_analyzed,
            'high_risk_patterns': len(high_risk_patterns),
            'pattern_bonus': pattern_bonus,
            'message': f'{obfuscated} obfuscated, {suspicious} suspicious files'
        }

        return min(30, risk), details

    def _calculate_webstore_risk(self, webstore_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from webstore reputation (max 5 points).

        Args:
            webstore_data: Webstore analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        if not webstore_data:
            return 0, {'message': 'No webstore data'}

        rating = None
        user_count = None
        
        if isinstance(webstore_data, dict):
            rating = webstore_data.get('rating')
            user_count = webstore_data.get('user_count')

        risk = 0
        rating_risk = 0
        users_risk = 0

        if rating is not None:
            try:
                rating_float = float(rating)
                if rating_float < 2.0:
                    rating_risk = 3
                    risk += 3
                elif rating_float < 3.0:
                    rating_risk = 2
                    risk += 2
            except (ValueError, TypeError):
                pass

        if user_count is not None:
            try:
                user_count_int = int(user_count)
                if user_count_int < 100:
                    users_risk = 2
                    risk += 2
            except (ValueError, TypeError):
                pass

        details = {
            'rating': rating,
            'user_count': user_count,
            'rating_risk': rating_risk,
            'users_risk': users_risk,
            'message': f'Rating: {rating}, Users: {user_count}'
        }

        return min(5, risk), details

    def _calculate_manifest_risk(self, manifest: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from manifest issues (max 5 points).

        Args:
            manifest: Parsed manifest.json

        Returns:
            Tuple of (risk_points, details_dict)
        """
        if not manifest:
            return 0, {'message': 'No manifest data'}

        risk = 0
        issues = []

        csp_risk = 0
        if not manifest.get('content_security_policy'):
            csp_risk = 3
            risk += 3
            issues.append('Missing Content Security Policy')

        mv_risk = 0
        manifest_version = manifest.get('manifest_version')
        if manifest_version == 2:
            mv_risk = 2  # MV2 is deprecated
            risk += 2
            issues.append('Using deprecated Manifest V2')

        details = {
            'manifest_version': manifest_version,
            'has_csp': bool(manifest.get('content_security_policy')),
            'csp_risk': csp_risk,
            'manifest_version_risk': mv_risk,
            'issues': issues,
            'message': ', '.join(issues) if issues else 'No manifest issues'
        }

        return min(5, risk), details

    def _calculate_chromestats_risk(self, chromestats_data: Dict) -> tuple[int, Dict]:
        """
        Calculate risk from Chrome Stats behavioral analysis (max 28 points).

        Args:
            chromestats_data: Chrome Stats analysis results

        Returns:
            Tuple of (risk_points, details_dict)
        """
        if not chromestats_data.get('enabled'):
            return 0, {'message': 'Chrome Stats not enabled'}

        if chromestats_data.get('error'):
            return 0, {'message': f"Chrome Stats error: {chromestats_data.get('error')}"}

        total_risk_score = chromestats_data.get('total_risk_score', 0)
        risk_indicators = chromestats_data.get('risk_indicators', [])
        overall_risk = chromestats_data.get('overall_risk_level', 'low')

        install_trends = chromestats_data.get('install_trends', {})
        rating_patterns = chromestats_data.get('rating_patterns', {})
        developer_reputation = chromestats_data.get('developer_reputation', {})

        details = {
            'overall_risk_level': overall_risk,
            'total_risk_score': total_risk_score,
            'risk_indicator_count': len(risk_indicators),
            'top_indicators': risk_indicators[:5],  # Top 5 indicators
            'uninstall_rate': install_trends.get('uninstall_rate', 0),
            'rating_change': rating_patterns.get('rating_change', 0),
            'developer_trust_score': developer_reputation.get('trust_score', 100),
            'message': f"{len(risk_indicators)} behavioral risk indicators detected"
        }

        return min(28, total_risk_score), details

    @staticmethod
    def _get_risk_level(score: int) -> str:
        """
        Determine risk level from score.

        Args:
            score: Risk score (0-100)

        Returns:
            Risk level string: 'low', 'medium', 'high', or 'critical'
        """
        if score >= 61:
            return 'critical'
        elif score >= 36:
            return 'high'
        elif score >= 16:
            return 'medium'
        else:
            return 'low'

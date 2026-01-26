#!/usr/bin/env python3
"""
Script to analyze Chrome extension for SAST patterns and generate signatures.
Handles obfuscated/minified JavaScript code.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set


class ExtensionSASTAnalyzer:
    """Analyzes Chrome extensions for security patterns."""

    def __init__(self, extension_path: str):
        self.extension_path = Path(extension_path)
        self.patterns_found: Dict[str, List[Dict]] = {}
        self.suspicious_indicators: Set[str] = set()

    def analyze(self) -> Dict:
        """Run full analysis on the extension."""
        print(f"Analyzing extension at: {self.extension_path}")
        
        # Find all JavaScript files
        js_files = list(self.extension_path.rglob("*.js"))
        print(f"Found {len(js_files)} JavaScript files")
        
        for js_file in js_files:
            print(f"\nAnalyzing: {js_file.name}")
            self._analyze_file(js_file)
        
        # Generate report
        report = self._generate_report()
        return report

    def _analyze_file(self, file_path: Path):
        """Analyze a single JavaScript file for patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_name = file_path.name
            
            # Check for obfuscation indicators
            self._check_obfuscation(content, file_name)
            
            # Check for suspicious patterns
            self._check_network_patterns(content, file_name)
            self._check_data_exfiltration(content, file_name)
            self._check_credential_theft(content, file_name)
            self._check_dom_manipulation(content, file_name)
            self._check_eval_patterns(content, file_name)
            self._check_storage_access(content, file_name)
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

    def _check_obfuscation(self, content: str, file_name: str):
        """Check for code obfuscation indicators."""
        patterns = {
            'hex_strings': r'\\x[0-9a-fA-F]{2}',
            'unicode_escapes': r'\\u[0-9a-fA-F]{4}',
            'mangled_vars': r'_0x[0-9a-fA-F]+',
            'short_vars': r'\b[a-z]_[0-9]+\b',
            'base64_strings': r'[A-Za-z0-9+/]{40,}={0,2}',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content)
            if len(matches) > 10:  # Threshold for suspicion
                self._add_finding('obfuscation', file_name, pattern_name, len(matches))
                self.suspicious_indicators.add(f"Heavy {pattern_name} usage")

    def _check_network_patterns(self, content: str, file_name: str):
        """Check for network communication patterns."""
        patterns = {
            'XMLHttpRequest': r'new\s+XMLHttpRequest\s*\(',
            'fetch': r'\bfetch\s*\(',
            'WebSocket': r'new\s+WebSocket\s*\(',
            'external_urls': r'https?://[^\s\'"]+',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content, re.IGNORECASE)
            if matches:
                self._add_finding('network', file_name, pattern_name, len(matches))
                if pattern_name == 'external_urls':
                    # Extract unique domains
                    domains = set()
                    for url in matches:
                        domain_match = re.search(r'https?://([^/\s\'"]+)', url)
                        if domain_match:
                            domains.add(domain_match.group(1))
                    self.suspicious_indicators.add(f"External domains: {', '.join(list(domains)[:5])}")

    def _check_data_exfiltration(self, content: str, file_name: str):
        """Check for data exfiltration patterns."""
        patterns = {
            'btoa': r'\bbtoa\s*\(',
            'atob': r'\batob\s*\(',
            'JSON.stringify': r'JSON\.stringify\s*\(',
            'FormData': r'new\s+FormData\s*\(',
            'Blob': r'new\s+Blob\s*\(',
            'FileReader': r'new\s+FileReader\s*\(',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content)
            if matches:
                self._add_finding('data_exfiltration', file_name, pattern_name, len(matches))

    def _check_credential_theft(self, content: str, file_name: str):
        """Check for credential theft patterns."""
        patterns = {
            'password_input': r'type\s*[=:]\s*["\']password["\']',
            'input_value': r'\.value\b',
            'addEventListener_input': r'addEventListener\s*\(\s*["\']input["\']',
            'addEventListener_change': r'addEventListener\s*\(\s*["\']change["\']',
            'addEventListener_blur': r'addEventListener\s*\(\s*["\']blur["\']',
            'querySelector_input': r'querySelector\s*\(\s*["\'][^"\']*input[^"\']*["\']',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content, re.IGNORECASE)
            if matches:
                self._add_finding('credential_theft', file_name, pattern_name, len(matches))

    def _check_dom_manipulation(self, content: str, file_name: str):
        """Check for DOM manipulation patterns."""
        patterns = {
            'innerHTML': r'\.innerHTML\s*=',
            'outerHTML': r'\.outerHTML\s*=',
            'document.write': r'document\.write\s*\(',
            'insertAdjacentHTML': r'\.insertAdjacentHTML\s*\(',
            'createElement': r'document\.createElement\s*\(',
            'appendChild': r'\.appendChild\s*\(',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content)
            if matches:
                self._add_finding('dom_manipulation', file_name, pattern_name, len(matches))

    def _check_eval_patterns(self, content: str, file_name: str):
        """Check for dynamic code execution patterns."""
        patterns = {
            'eval': r'\beval\s*\(',
            'Function': r'new\s+Function\s*\(',
            'setTimeout_string': r'setTimeout\s*\(\s*["\']',
            'setInterval_string': r'setInterval\s*\(\s*["\']',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content)
            if matches:
                self._add_finding('dynamic_execution', file_name, pattern_name, len(matches))

    def _check_storage_access(self, content: str, file_name: str):
        """Check for storage access patterns."""
        patterns = {
            'localStorage': r'\blocalStorage\.',
            'sessionStorage': r'\bsessionStorage\.',
            'chrome.storage': r'chrome\.storage\.',
            'indexedDB': r'\bindexedDB\.',
            'cookies': r'document\.cookie',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, content)
            if matches:
                self._add_finding('storage_access', file_name, pattern_name, len(matches))

    def _add_finding(self, category: str, file_name: str, pattern: str, count: int):
        """Add a finding to the results."""
        if category not in self.patterns_found:
            self.patterns_found[category] = []
        
        self.patterns_found[category].append({
            'file': file_name,
            'pattern': pattern,
            'count': count
        })

    def _generate_report(self) -> Dict:
        """Generate analysis report."""
        report = {
            'extension_path': str(self.extension_path),
            'total_categories': len(self.patterns_found),
            'suspicious_indicators': list(self.suspicious_indicators),
            'patterns_by_category': {},
            'recommended_sast_rules': []
        }
        
        # Organize patterns by category
        for category, findings in self.patterns_found.items():
            report['patterns_by_category'][category] = {
                'total_findings': len(findings),
                'files_affected': len(set(f['file'] for f in findings)),
                'patterns': {}
            }
            
            # Count patterns
            for finding in findings:
                pattern = finding['pattern']
                if pattern not in report['patterns_by_category'][category]['patterns']:
                    report['patterns_by_category'][category]['patterns'][pattern] = 0
                report['patterns_by_category'][category]['patterns'][pattern] += finding['count']
        
        # Generate recommended SAST rules
        report['recommended_sast_rules'] = self._generate_rule_recommendations()
        
        return report

    def _generate_rule_recommendations(self) -> List[str]:
        """Generate SAST rule recommendations based on findings."""
        recommendations = []
        
        if 'obfuscation' in self.patterns_found:
            recommendations.append('banking.obfuscation.hex_encoded_strings')
            recommendations.append('c2.exfiltration.base64_encoded_data')
        
        if 'network' in self.patterns_found:
            recommendations.append('c2.exfiltration.xhr_post_request')
            recommendations.append('c2.exfiltration.fetch_post_request')
        
        if 'credential_theft' in self.patterns_found:
            recommendations.append('banking.credential_theft.password_input_listener')
            recommendations.append('banking.credential_theft.form_data_capture')
        
        if 'data_exfiltration' in self.patterns_found:
            recommendations.append('c2.exfiltration.base64_encoded_data')
            recommendations.append('banking.data_exfiltration.formdata_collection')
        
        if 'dom_manipulation' in self.patterns_found:
            recommendations.append('banking.dom_manipulation.innerhtml_injection')
        
        if 'dynamic_execution' in self.patterns_found:
            recommendations.append('c2.exfiltration.dynamic_script_loading')
            recommendations.append('banking.code_injection.eval_usage')
        
        return list(set(recommendations))  # Remove duplicates


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python check_extension_sast.py <extension_path>")
        sys.exit(1)
    
    extension_path = sys.argv[1]
    
    if not os.path.exists(extension_path):
        print(f"Error: Extension path not found: {extension_path}")
        sys.exit(1)
    
    analyzer = ExtensionSASTAnalyzer(extension_path)
    report = analyzer.analyze()
    
    # Print report
    print("\n" + "="*80)
    print("SAST ANALYSIS REPORT")
    print("="*80)
    
    print(f"\nExtension: {report['extension_path']}")
    print(f"Categories found: {report['total_categories']}")
    
    if report['suspicious_indicators']:
        print("\n⚠️  SUSPICIOUS INDICATORS:")
        for indicator in report['suspicious_indicators']:
            print(f"  - {indicator}")
    
    print("\n📊 PATTERNS BY CATEGORY:")
    for category, data in report['patterns_by_category'].items():
        print(f"\n  {category.upper()}:")
        print(f"    Total findings: {data['total_findings']}")
        print(f"    Files affected: {data['files_affected']}")
        print(f"    Patterns detected:")
        for pattern, count in sorted(data['patterns'].items(), key=lambda x: x[1], reverse=True):
            print(f"      - {pattern}: {count} occurrences")
    
    print("\n🎯 RECOMMENDED SAST RULES:")
    for rule in report['recommended_sast_rules']:
        print(f"  - {rule}")
    
    # Save to JSON
    output_file = "extension_sast_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Full report saved to: {output_file}")


if __name__ == "__main__":
    main()

# Made with Bob

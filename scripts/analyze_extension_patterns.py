#!/usr/bin/env python3
"""
Script to analyze Chrome extension and identify SAST signature patterns.
This helps determine which Semgrep rules should be added to detect malicious behavior.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ExtensionPatternAnalyzer:
    """Analyzes extension code to identify security patterns for SAST rules."""

    def __init__(self, extension_dir: str):
        self.extension_dir = Path(extension_dir)
        self.js_files = []
        self.patterns_found = defaultdict(list)
        
    def find_js_files(self) -> List[Path]:
        """Find all JavaScript files in the extension."""
        js_files = []
        for ext in ['*.js', '*.mjs']:
            js_files.extend(self.extension_dir.rglob(ext))
        
        # Filter out minified and library files
        filtered = []
        for f in js_files:
            name = f.name.lower()
            path_str = str(f).lower()
            
            # Skip common library patterns
            skip_patterns = [
                'jquery', 'bootstrap', 'lodash', 'angular', 'react', 'vue',
                '.min.js', '.bundle.js', 'vendor/', 'lib/', 'node_modules/'
            ]
            
            if not any(pattern in name or pattern in path_str for pattern in skip_patterns):
                filtered.append(f)
        
        self.js_files = filtered
        logger.info(f"Found {len(filtered)} JavaScript files to analyze")
        return filtered

    def analyze_api_usage(self, content: str, file_path: Path) -> Dict[str, List[str]]:
        """Analyze Chrome API usage patterns."""
        apis = {
            'chrome.cookies': [],
            'chrome.webRequest': [],
            'chrome.storage': [],
            'chrome.tabs': [],
            'chrome.runtime': [],
            'chrome.identity': [],
            'chrome.downloads': [],
            'chrome.history': [],
            'chrome.bookmarks': [],
        }
        
        for api in apis.keys():
            pattern = rf'{re.escape(api)}\.(\w+)'
            matches = re.finditer(pattern, content)
            for match in matches:
                method = match.group(1)
                apis[api].append(f"{api}.{method}")
        
        return {k: list(set(v)) for k, v in apis.items() if v}

    def analyze_network_patterns(self, content: str, file_path: Path) -> List[Dict]:
        """Analyze network communication patterns."""
        patterns = []
        
        # fetch() calls
        fetch_pattern = r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        for match in re.finditer(fetch_pattern, content):
            url = match.group(1)
            patterns.append({
                'type': 'fetch',
                'url': url,
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # XMLHttpRequest
        xhr_pattern = r'XMLHttpRequest\s*\(\s*\)'
        if re.search(xhr_pattern, content):
            patterns.append({
                'type': 'XMLHttpRequest',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # WebSocket
        ws_pattern = r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        for match in re.finditer(ws_pattern, content):
            url = match.group(1)
            patterns.append({
                'type': 'WebSocket',
                'url': url,
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # navigator.sendBeacon
        beacon_pattern = r'navigator\.sendBeacon\s*\('
        if re.search(beacon_pattern, content):
            patterns.append({
                'type': 'sendBeacon',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        return patterns

    def analyze_dom_manipulation(self, content: str, file_path: Path) -> List[Dict]:
        """Analyze DOM manipulation patterns."""
        patterns = []
        
        # innerHTML usage
        if 'innerHTML' in content:
            patterns.append({
                'type': 'innerHTML',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # eval() usage
        eval_pattern = r'\beval\s*\('
        if re.search(eval_pattern, content):
            patterns.append({
                'type': 'eval',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # new Function()
        func_pattern = r'new\s+Function\s*\('
        if re.search(func_pattern, content):
            patterns.append({
                'type': 'new Function',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # document.write
        if 'document.write' in content:
            patterns.append({
                'type': 'document.write',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        return patterns

    def analyze_data_access(self, content: str, file_path: Path) -> List[Dict]:
        """Analyze data access patterns."""
        patterns = []
        
        # localStorage/sessionStorage
        storage_pattern = r'(localStorage|sessionStorage)\.(getItem|setItem|removeItem)'
        for match in re.finditer(storage_pattern, content):
            patterns.append({
                'type': f'{match.group(1)}.{match.group(2)}',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # document.cookie
        if 'document.cookie' in content:
            patterns.append({
                'type': 'document.cookie',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # Password field access
        pwd_pattern = r'input\[type=[\'"]password[\'"]\]'
        if re.search(pwd_pattern, content):
            patterns.append({
                'type': 'password_field_access',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # Form data access
        if 'FormData' in content:
            patterns.append({
                'type': 'FormData',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        return patterns

    def analyze_obfuscation(self, content: str, file_path: Path) -> List[Dict]:
        """Analyze code obfuscation patterns."""
        patterns = []
        
        # Base64 encoding
        if 'btoa(' in content or 'atob(' in content:
            patterns.append({
                'type': 'base64_encoding',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # String concatenation patterns (potential obfuscation)
        concat_pattern = r'[\'"][^\'"]{1,3}[\'"]\s*\+\s*[\'"][^\'"]{1,3}[\'"]\s*\+\s*[\'"][^\'"]{1,3}[\'"]'
        if re.search(concat_pattern, content):
            patterns.append({
                'type': 'string_concatenation',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # Hex encoding
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        if re.search(hex_pattern, content):
            patterns.append({
                'type': 'hex_encoding',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        return patterns

    def analyze_event_listeners(self, content: str, file_path: Path) -> List[Dict]:
        """Analyze event listener patterns."""
        patterns = []
        
        # addEventListener patterns
        listener_pattern = r'addEventListener\s*\(\s*[\'"](\w+)[\'"]'
        for match in re.finditer(listener_pattern, content):
            event_type = match.group(1)
            patterns.append({
                'type': 'addEventListener',
                'event': event_type,
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        # MutationObserver
        if 'MutationObserver' in content:
            patterns.append({
                'type': 'MutationObserver',
                'file': str(file_path.relative_to(self.extension_dir))
            })
        
        return patterns

    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single JavaScript file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            results = {
                'file': str(file_path.relative_to(self.extension_dir)),
                'size': len(content),
                'api_usage': self.analyze_api_usage(content, file_path),
                'network_patterns': self.analyze_network_patterns(content, file_path),
                'dom_manipulation': self.analyze_dom_manipulation(content, file_path),
                'data_access': self.analyze_data_access(content, file_path),
                'obfuscation': self.analyze_obfuscation(content, file_path),
                'event_listeners': self.analyze_event_listeners(content, file_path),
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return None

    def generate_semgrep_rule_suggestions(self, all_results: List[Dict]) -> List[Dict]:
        """Generate Semgrep rule suggestions based on patterns found."""
        suggestions = []
        
        # Aggregate patterns across all files
        all_apis = defaultdict(set)
        all_network = []
        all_dom = []
        all_data = []
        all_obfuscation = []
        all_events = []
        
        for result in all_results:
            if not result:
                continue
                
            # Collect API usage
            for api, methods in result.get('api_usage', {}).items():
                all_apis[api].update(methods)
            
            all_network.extend(result.get('network_patterns', []))
            all_dom.extend(result.get('dom_manipulation', []))
            all_data.extend(result.get('data_access', []))
            all_obfuscation.extend(result.get('obfuscation', []))
            all_events.extend(result.get('event_listeners', []))
        
        # Generate suggestions based on findings
        if all_apis.get('chrome.cookies'):
            suggestions.append({
                'rule_id': 'cookie.theft.chrome_cookies_api',
                'reason': f"Extension uses chrome.cookies API: {list(all_apis['chrome.cookies'])}",
                'severity': 'CRITICAL',
                'exists': True  # This rule already exists
            })
        
        if all_apis.get('chrome.webRequest'):
            suggestions.append({
                'rule_id': 'banking.ext.webrequest.redirect',
                'reason': f"Extension uses chrome.webRequest API: {list(all_apis['chrome.webRequest'])}",
                'severity': 'ERROR',
                'exists': True
            })
        
        if any(p['type'] == 'document.cookie' for p in all_data):
            suggestions.append({
                'rule_id': 'cookie.theft.document_cookie_access',
                'reason': "Extension accesses document.cookie",
                'severity': 'CRITICAL',
                'exists': True
            })
        
        if any(p['type'] in ['localStorage.getItem', 'sessionStorage.getItem'] for p in all_data):
            suggestions.append({
                'rule_id': 'credential.theft.storage_access',
                'reason': "Extension accesses browser storage (localStorage/sessionStorage)",
                'severity': 'CRITICAL',
                'exists': True
            })
        
        if any(p['type'] == 'WebSocket' for p in all_network):
            suggestions.append({
                'rule_id': 'c2.exfiltration.websocket_connection',
                'reason': "Extension uses WebSocket connections",
                'severity': 'ERROR',
                'exists': True
            })
        
        if any(p['type'] == 'eval' for p in all_dom):
            suggestions.append({
                'rule_id': 'banking.obfuscation.eval_newfunc',
                'reason': "Extension uses eval() - potential code obfuscation",
                'severity': 'ERROR',
                'exists': True
            })
        
        if any(p['type'] == 'base64_encoding' for p in all_obfuscation):
            suggestions.append({
                'rule_id': 'c2.exfiltration.base64_encoded_data',
                'reason': "Extension uses base64 encoding",
                'severity': 'CRITICAL',
                'exists': True
            })
        
        if all_apis.get('chrome.identity'):
            suggestions.append({
                'rule_id': 'credential.theft.chrome_identity_api',
                'reason': f"Extension uses chrome.identity API: {list(all_apis['chrome.identity'])}",
                'severity': 'ERROR',
                'exists': True
            })
        
        # Check for patterns that might need NEW rules
        if any(p['type'] == 'fetch' and 'google' in p.get('url', '').lower() for p in all_network):
            suggestions.append({
                'rule_id': 'NEW: google_api_access',
                'reason': "Extension makes fetch requests to Google APIs",
                'severity': 'WARNING',
                'exists': False,
                'pattern': 'fetch() calls to google.com domains'
            })
        
        return suggestions

    def run_analysis(self) -> Dict:
        """Run complete analysis on the extension."""
        logger.info(f"Analyzing extension at: {self.extension_dir}")
        
        # Find JavaScript files
        js_files = self.find_js_files()
        
        if not js_files:
            logger.warning("No JavaScript files found to analyze")
            return {}
        
        # Analyze each file
        all_results = []
        for js_file in js_files:
            logger.info(f"Analyzing: {js_file.relative_to(self.extension_dir)}")
            result = self.analyze_file(js_file)
            if result:
                all_results.append(result)
        
        # Generate rule suggestions
        suggestions = self.generate_semgrep_rule_suggestions(all_results)
        
        return {
            'extension_dir': str(self.extension_dir),
            'files_analyzed': len(all_results),
            'detailed_results': all_results,
            'rule_suggestions': suggestions
        }

    def print_report(self, analysis: Dict):
        """Print analysis report."""
        print("\n" + "="*80)
        print("EXTENSION PATTERN ANALYSIS REPORT")
        print("="*80)
        print(f"\nExtension Directory: {analysis['extension_dir']}")
        print(f"Files Analyzed: {analysis['files_analyzed']}")
        
        print("\n" + "-"*80)
        print("SEMGREP RULE SUGGESTIONS")
        print("-"*80)
        
        suggestions = analysis.get('rule_suggestions', [])
        if not suggestions:
            print("\nNo specific rule suggestions - extension appears clean or uses uncommon patterns")
        else:
            existing_rules = [s for s in suggestions if s.get('exists')]
            new_rules = [s for s in suggestions if not s.get('exists')]
            
            if existing_rules:
                print(f"\n✓ EXISTING RULES THAT SHOULD TRIGGER ({len(existing_rules)}):")
                for i, sugg in enumerate(existing_rules, 1):
                    print(f"\n{i}. Rule ID: {sugg['rule_id']}")
                    print(f"   Severity: {sugg['severity']}")
                    print(f"   Reason: {sugg['reason']}")
            
            if new_rules:
                print(f"\n⚠ NEW RULES TO CONSIDER ADDING ({len(new_rules)}):")
                for i, sugg in enumerate(new_rules, 1):
                    print(f"\n{i}. Rule ID: {sugg['rule_id']}")
                    print(f"   Severity: {sugg['severity']}")
                    print(f"   Reason: {sugg['reason']}")
                    if 'pattern' in sugg:
                        print(f"   Pattern: {sugg['pattern']}")
        
        print("\n" + "-"*80)
        print("DETAILED FINDINGS BY FILE")
        print("-"*80)
        
        for result in analysis.get('detailed_results', []):
            print(f"\n📄 {result['file']} ({result['size']} bytes)")
            
            if result.get('api_usage'):
                print("  Chrome APIs:")
                for api, methods in result['api_usage'].items():
                    print(f"    - {api}: {', '.join(methods)}")
            
            if result.get('network_patterns'):
                print("  Network Patterns:")
                for pattern in result['network_patterns']:
                    print(f"    - {pattern['type']}: {pattern.get('url', 'N/A')}")
            
            if result.get('data_access'):
                print("  Data Access:")
                for pattern in result['data_access']:
                    print(f"    - {pattern['type']}")
            
            if result.get('obfuscation'):
                print("  Obfuscation:")
                for pattern in result['obfuscation']:
                    print(f"    - {pattern['type']}")
        
        print("\n" + "="*80)


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_extension_patterns.py <extension_directory>")
        print("\nExample:")
        print("  python analyze_extension_patterns.py extensions_storage/extracted_extension")
        sys.exit(1)
    
    extension_dir = sys.argv[1]
    
    if not os.path.exists(extension_dir):
        print(f"Error: Directory not found: {extension_dir}")
        sys.exit(1)
    
    analyzer = ExtensionPatternAnalyzer(extension_dir)
    analysis = analyzer.run_analysis()
    analyzer.print_report(analysis)
    
    # Save results to JSON
    output_file = "extension_pattern_analysis.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2)
    print(f"\n✓ Full analysis saved to: {output_file}")


if __name__ == "__main__":
    main()

# Made with Bob

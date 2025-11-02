"""Static Application Security Testing (SAST) Analyzer"""

import json
import logging
from typing import Dict, Optional, List
import subprocess
import os
import fnmatch
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from threatxtension.core.analyzers import BaseAnalyzer

load_dotenv()
logger = logging.getLogger(__name__)


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzes JavaScript files in Chrome extensions using SAST techniques."""

    def __init__(self):
        """Initialize the JavaScriptAnalyzer."""
        super().__init__(name="JavaScriptAnalyzer")
        self.sast_config = self._load_sast_config()
        self.semgrep_config = self._get_semgrep_config()

    @staticmethod
    def _load_sast_config() -> Dict:
        """Load SAST configuration from JSON file."""
        config_path = Path(__file__).parent.parent.parent / "config" / "sast_config.json"
        try:
            with open(config_path, "r", encoding="utf-8") as file:
                config = json.load(file)
                logger.info("Loaded SAST configuration from %s", config_path)
                return config
        except FileNotFoundError:
            logger.warning("SAST config file not found at %s, using default settings", config_path)
            return {"enabled": False, "exclusion_patterns": {}, "max_file_size_kb": 500}
        except json.JSONDecodeError as exc:
            logger.error("Error parsing SAST config file: %s", exc)
            return {"enabled": False, "exclusion_patterns": {}, "max_file_size_kb": 500}

    def _get_semgrep_config(self) -> str:
        """Get the Semgrep configuration to use for scanning."""
        config_name = self.sast_config.get("semgrep_config", "javascript")
        config_options = self.sast_config.get("semgrep_config_options", {})

        semgrep_config = config_options.get(config_name, "p/javascript")

        # If it's a relative path (custom ruleset), resolve it
        if not semgrep_config.startswith("p/") and not semgrep_config == "auto":
            config_path = Path(__file__).parent.parent.parent / semgrep_config
            if config_path.exists():
                semgrep_config = str(config_path)
                logger.info("Using custom Semgrep ruleset: %s", semgrep_config)
            else:
                logger.warning(
                    "Custom ruleset not found at %s, falling back to p/javascript", config_path
                )
                semgrep_config = "p/javascript"
        else:
            logger.info("Using Semgrep config: %s", semgrep_config)

        return semgrep_config

    def _should_skip_file(self, file_path: str) -> tuple[bool, Optional[str]]:
        """
        Check if a file should be skipped based on exclusion patterns.

        Returns:
            tuple: (should_skip: bool, reason: str or None)
        """
        if not self.sast_config.get("enabled", True):
            return False, None

        # Extract filename and path components
        file_name = file_path.split("/")[-1]
        file_path_lower = file_path.lower()

        exclusion_patterns = self.sast_config.get("exclusion_patterns", {})

        # Check path segments (e.g., lib/, vendor/, node_modules/)
        path_segments = exclusion_patterns.get("path_segments", [])
        for segment in path_segments:
            if f"/{segment}" in file_path_lower or file_path_lower.startswith(segment):
                return True, f"path contains '{segment}'"

        # Check file patterns (e.g., *.min.js, *.bundle.js, chunk-*.js)
        file_patterns = exclusion_patterns.get("file_patterns", [])
        for pattern in file_patterns:
            # Use fnmatch for full glob pattern support
            if fnmatch.fnmatch(file_name.lower(), pattern.lower()):
                return True, f"matches pattern '{pattern}'"

        # Check library names (e.g., jquery, bootstrap)
        library_names = exclusion_patterns.get("library_names", [])
        for lib_name in library_names:
            if lib_name.lower() in file_name.lower():
                return True, f"matches library name '{lib_name}'"

        # Check file size if file exists
        max_size_kb = self.sast_config.get("max_file_size_kb", 500)
        if os.path.exists(file_path):
            file_size_kb = os.path.getsize(file_path) / 1024
            if file_size_kb > max_size_kb:
                return True, f"file size ({file_size_kb:.1f}KB) exceeds threshold ({max_size_kb}KB)"

        return False, None

    @staticmethod
    def _extract_javascript_files(extension_dir: str, manifest: Dict) -> List:
        """Extract JavaScript file paths from the extension manifest."""
        js_files = set()  # Use set for automatic deduplication

        # Background scripts
        if "background" in manifest:
            bg = manifest["background"]
            # Manifest V3 uses service_worker
            if "service_worker" in bg:
                js_files.add(bg["service_worker"])
            # Manifest V2 uses scripts array
            if "scripts" in bg:
                js_files.update(bg["scripts"])
            # TODO: Handle scripts embedded in HTML if needed

        # Content scripts
        if "content_scripts" in manifest:
            for content_script in manifest["content_scripts"]:
                if "js" in content_script:
                    js_files.update(content_script["js"])

        # TODO: Handle other script locations like popup, options, etc.

        # Convert to absolute paths and sort for consistent ordering
        js_file_paths = sorted([f"{extension_dir}/{file_path}" for file_path in js_files])
        logger.info("Extracted %d unique JavaScript files from manifest", len(js_file_paths))
        return js_file_paths

    @staticmethod
    def _is_semgrep_installed() -> bool:
        """Check if Semgrep is installed."""
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, text=True, check=True)
            return True
        except FileNotFoundError:
            logger.error(
                "Semgrep is not installed or not found in PATH. Install 'semgrep' python package."
            )
            return False

    @staticmethod
    def _run_semgrep_scan(file_path: str, config: str = "auto") -> Optional[Dict]:
        """Run Semgrep scan on a single JavaScript file."""
        try:
            cmd = [
                "semgrep",
                "--config",
                config,
                "--json",
                file_path,
            ]
            logger.info("Running SAST scan on file: %s with rule %s", file_path, config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.stdout:
                findings = json.loads(result.stdout)
                return findings
            else:
                logger.info("No findings from Semgrep scan on file: %s", file_path)
                return None

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out for file: %s", file_path)
            return None
        except Exception as exc:
            logger.error("Error running Semgrep scan on file %s: %s", file_path, exc)
            return None

    @staticmethod
    def _get_relative_path(file_path: str, base_dir: str) -> str:
        """Get relative path from base directory."""
        if file_path.startswith(base_dir):
            # Remove base_dir and leading slash
            rel_path = file_path[len(base_dir) :].lstrip("/")
            return rel_path
        # Fallback to just filename if path doesn't start with base_dir
        return file_path.split("/")[-1]

    @staticmethod
    def _run_semgrep_batch_scan(
        file_paths: List[str], extension_dir: str, config: str = "auto", timeout: int = 300
    ) -> Dict[str, List]:
        """Run Semgrep scan on multiple JavaScript files in a single batch."""
        if not file_paths:
            return {}

        try:
            cmd = [
                "semgrep",
                "--config",
                config,
                "--json",
                *file_paths,  # Pass all files to Semgrep
            ]
            logger.info("Running batch SAST scan on %d files with rule %s", len(file_paths), config)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,  # Don't raise on non-zero exit (Semgrep returns non-zero if findings found)
            )

            if result.stdout:
                findings_data = json.loads(result.stdout)

                # Map findings back to individual files using relative paths
                findings_by_file = {}
                for file_path in file_paths:
                    rel_path = JavaScriptAnalyzer._get_relative_path(file_path, extension_dir)
                    findings_by_file[rel_path] = []

                if "results" in findings_data:
                    for finding in findings_data["results"]:
                        if "path" in finding:
                            rel_path = JavaScriptAnalyzer._get_relative_path(
                                finding["path"], extension_dir
                            )
                            if rel_path in findings_by_file:
                                findings_by_file[rel_path].append(finding)

                logger.info(
                    "Batch scan completed: found findings in %d/%d files",
                    sum(1 for f in findings_by_file.values() if f),
                    len(file_paths),
                )
                return findings_by_file
            else:
                logger.info("No findings from batch Semgrep scan")
                return {
                    JavaScriptAnalyzer._get_relative_path(fp, extension_dir): []
                    for fp in file_paths
                }

        except subprocess.TimeoutExpired:
            logger.error(
                "Batch Semgrep scan timed out after %d seconds for %d files",
                timeout,
                len(file_paths),
            )
            return {}
        except Exception as exc:
            logger.error("Error running batch Semgrep scan: %s", exc)
            return {}

    def _run_parallel_batch_scans(
        self, file_paths: List[str], extension_dir: str, config: str = "auto", max_workers: int = 4
    ) -> Dict[str, List]:
        """Run Semgrep scans on files in parallel batches."""
        if not file_paths:
            return {}

        # Calculate timeout per batch based on files per batch
        scanning_config = self.sast_config.get("scanning", {})
        timeout_per_file = scanning_config.get("batch_timeout_per_file_seconds", 10)

        # Split files into batches for parallel processing
        batch_size = max(1, len(file_paths) // max_workers)
        batches = [file_paths[i : i + batch_size] for i in range(0, len(file_paths), batch_size)]

        logger.info(
            "Splitting %d files into %d batches for parallel scanning",
            len(file_paths),
            len(batches),
        )

        all_findings = {}

        # Run batches in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(
                    self._run_semgrep_batch_scan,
                    batch,
                    extension_dir,
                    config,
                    len(batch) * timeout_per_file + 60,  # Timeout per batch
                ): batch
                for batch in batches
            }

            # Collect results as they complete
            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    batch_findings = future.result()
                    all_findings.update(batch_findings)
                    logger.info("Completed parallel batch scan of %d files", len(batch))
                except Exception as exc:
                    logger.error(
                        "Parallel batch scan failed for batch of %d files: %s", len(batch), exc
                    )

        return all_findings

    def _filter_files(
        self, file_paths: List[str], extension_dir: str
    ) -> tuple[List[str], List[Dict]]:
        """Filter out library files and large files based on exclusion patterns."""
        files_to_scan = []
        skipped_files = []

        for file_path in file_paths:
            should_skip, reason = self._should_skip_file(file_path)
            if should_skip:
                rel_path = self._get_relative_path(file_path, extension_dir)
                skipped_files.append({"file": rel_path, "reason": reason})
            else:
                files_to_scan.append(file_path)

        logger.info(
            "Filtered %d JavaScript files: %d to scan, %d skipped (libraries/large files)",
            len(file_paths),
            len(files_to_scan),
            len(skipped_files),
        )

        return files_to_scan, skipped_files

    @staticmethod
    def _aggregate_findings(all_findings: Dict[str, List]) -> Dict:
        """Aggregate SAST findings by severity and count."""
        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        total_findings = 0
        files_with_findings = set()

        for file_path, findings in all_findings.items():
            if findings:
                files_with_findings.add(file_path)
                for finding in findings:
                    total_findings += 1
                    severity = finding.get("extra", {}).get("severity", "INFO")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    else:
                        # Handle unknown severity as WARNING
                        severity_counts["WARNING"] += 1

        return {
            "total_findings": total_findings,
            "by_severity": severity_counts,
            "files_with_findings": len(files_with_findings),
        }

    @staticmethod
    def _format_findings_for_llm(all_findings: Dict[str, List], top_n: int = 10) -> str:
        """Format top N findings for LLM prompt."""
        # Flatten all findings with file context
        formatted_findings = []

        for file_path, findings in all_findings.items():
            for finding in findings:
                severity = finding.get("extra", {}).get("severity", "INFO")
                message = finding.get("extra", {}).get("message", "No message")
                line = finding.get("start", {}).get("line", "?")
                category = finding.get("extra", {}).get("metadata", {}).get("category", "unknown")

                formatted_findings.append(
                    {
                        "severity": severity,
                        "file": file_path,
                        "line": line,
                        "message": message,
                        "category": category,
                    }
                )

        # Sort by severity priority (CRITICAL > ERROR > WARNING > INFO)
        severity_order = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
        formatted_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        # Take top N and format as text
        top_findings = formatted_findings[:top_n]
        if not top_findings:
            return "No findings detected."

        findings_text = []
        for finding in top_findings:
            findings_text.append(
                f"{finding['file']}:{finding['line']} - "
                f"[{finding['severity']}] {finding['message']} (category: {finding['category']})"
            )

        return "\n".join(findings_text)

    def _summarize_sast_findings(
        self, all_findings: Dict[str, List], files_scanned: int, metadata: Optional[Dict] = None
    ) -> Optional[str]:
        """Generate LLM-based summary of SAST findings."""
        from threatxtension.llm.prompts import get_prompts
        from threatxtension.llm.clients import get_chat_llm_client
        from langchain_core.output_parsers import StrOutputParser
        from langchain_core.prompts import PromptTemplate

        try:
            # Aggregate findings
            stats = self._aggregate_findings(all_findings)

            # If no findings, return simple message
            if stats["total_findings"] == 0:
                return "[RISK: LOW] No security findings detected in SAST analysis."

            # Format findings for LLM
            findings_details = self._format_findings_for_llm(all_findings, top_n=10)

            # Get extension name from metadata
            extension_name = "Unknown Extension"
            if metadata:
                extension_name = metadata.get("name", "Unknown Extension")

            # Load prompt
            prompts = get_prompts("sast_analysis.yaml")
            template = PromptTemplate.from_template(prompts["sast_analysis_prompt"])

            # Get LLM client
            model_name = os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
            model_parameters = {"max_tokens": 500, "temperature": 0.1}
            llm = get_chat_llm_client(model_name=model_name, model_parameters=model_parameters)

            # Create chain
            chain = template | llm | StrOutputParser()

            # Invoke LLM
            summary = chain.invoke(
                {
                    "extension_name": extension_name,
                    "files_scanned": files_scanned,
                    "files_with_findings": stats["files_with_findings"],
                    "critical_count": stats["by_severity"]["CRITICAL"],
                    "error_count": stats["by_severity"]["ERROR"],
                    "warning_count": stats["by_severity"]["WARNING"],
                    "info_count": stats["by_severity"]["INFO"],
                    "findings_details": findings_details,
                }
            )

            logger.info("Generated SAST summary with LLM")
            return summary.strip()

        except Exception as exc:
            logger.error("Error generating SAST summary: %s", exc)
            return None

    def analyze(
        self, extension_dir: str, manifest: Optional[Dict] = None, metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Analyze JavaScript files in the extension directory using SAST."""

        if manifest is None:
            return None

        is_semgrep_available = self._is_semgrep_installed()
        if not is_semgrep_available:
            return None

        js_files = self._extract_javascript_files(extension_dir, manifest)
        files_to_scan, skipped_files = self._filter_files(js_files, extension_dir)

        if not files_to_scan:
            logger.info("No files to scan after filtering")
            return {
                "sast_findings": {},
            }

        all_findings = {}

        # Get scanning configuration
        scanning_config = self.sast_config.get("scanning", {})
        batch_enabled = scanning_config.get("batch_enabled", True)
        parallel_enabled = scanning_config.get("parallel_enabled", True)
        max_workers = scanning_config.get("max_parallel_workers", 4)
        timeout_per_file = scanning_config.get("batch_timeout_per_file_seconds", 10)

        # Choose scanning strategy based on configuration
        if parallel_enabled and len(files_to_scan) > max_workers:
            # Use parallel batch scanning for better performance
            logger.info("Using parallel batch scanning with %d workers", max_workers)
            all_findings = self._run_parallel_batch_scans(
                file_paths=files_to_scan,
                extension_dir=extension_dir,
                config=self.semgrep_config,
                max_workers=max_workers,
            )
        elif batch_enabled:
            # Use single batch scan
            logger.info("Using batch scanning for %d files", len(files_to_scan))
            timeout = len(files_to_scan) * timeout_per_file + 60
            all_findings = self._run_semgrep_batch_scan(
                file_paths=files_to_scan,
                extension_dir=extension_dir,
                config=self.semgrep_config,
                timeout=timeout,
            )
        else:
            # Fall back to sequential scanning
            logger.info("Using sequential scanning (batch/parallel disabled)")
            for file_path in files_to_scan:
                security_findings = self._run_semgrep_scan(
                    file_path=file_path, config=self.semgrep_config
                )
                rel_path = self._get_relative_path(file_path, extension_dir)
                if security_findings and "results" in security_findings:
                    all_findings[rel_path] = security_findings["results"]
                else:
                    all_findings[rel_path] = []

        # Generate LLM summary of findings
        sast_analysis = self._summarize_sast_findings(
            all_findings=all_findings, files_scanned=len(files_to_scan), metadata=metadata
        )

        return {
            "sast_analysis": sast_analysis,
        }

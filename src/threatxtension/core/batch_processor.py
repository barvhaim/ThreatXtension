"""
Batch Processing System

This module provides batch processing capabilities for analyzing multiple Chrome extensions.
"""

import json
import csv
import uuid
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.console import Console

from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowState, WorkflowStatus

logger = logging.getLogger(__name__)
console = Console()


class BatchProcessor:
    """Handles batch processing of multiple Chrome extensions."""

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the batch processor.

        Args:
            output_dir: Directory to store batch results. Defaults to './batch_results'
        """
        self.output_dir = Path(output_dir) if output_dir else Path("./batch_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.workflow_graph = build_graph()

    def process_batch(
        self,
        extension_list: List[str],
        batch_id: Optional[str] = None,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> Dict:
        """
        Process a batch of extensions.

        Args:
            extension_list: List of extension URLs, IDs, or file paths
            batch_id: Optional batch identifier. Generated if not provided.
            parallel: Whether to process extensions in parallel
            max_workers: Maximum number of parallel workers

        Returns:
            Dict containing batch results with status, results, and summary
        """
        batch_id = batch_id or str(uuid.uuid4())
        start_time = datetime.utcnow().isoformat()

        logger.info(f"Starting batch {batch_id} with {len(extension_list)} extensions")

        batch_state = {
            "batch_id": batch_id,
            "start_time": start_time,
            "total_extensions": len(extension_list),
            "completed": 0,
            "failed": 0,
            "status": "running",
            "results": [],
        }

        # Save initial batch state
        self._save_batch_state(batch_id, batch_state)

        if parallel:
            results = self._process_parallel(extension_list, batch_id, max_workers)
        else:
            results = self._process_sequential(extension_list, batch_id)

        # Update batch state with results
        batch_state["results"] = results
        batch_state["completed"] = sum(1 for r in results if r["status"] == "completed")
        batch_state["failed"] = sum(1 for r in results if r["status"] == "failed")
        batch_state["end_time"] = datetime.utcnow().isoformat()
        batch_state["status"] = "completed"

        # Save final batch state
        self._save_batch_state(batch_id, batch_state)

        # Generate batch report
        report_path = self.generate_batch_report(batch_state, batch_id)
        batch_state["report_path"] = str(report_path)

        logger.info(
            f"Batch {batch_id} completed: {batch_state['completed']} succeeded, "
            f"{batch_state['failed']} failed"
        )

        return batch_state

    def process_from_file(
        self, input_file: str, parallel: bool = True, max_workers: int = 4
    ) -> Dict:
        """
        Process extensions from a file (TXT, CSV, or JSON format).

        Args:
            input_file: Path to file containing extension identifiers
                - TXT: One extension per line
                - CSV: Must have 'url', 'id', or 'path' column
                - JSON: Array of strings or objects with 'url'/'id'/'path' field
            parallel: Whether to process in parallel
            max_workers: Maximum number of parallel workers

        Returns:
            Dict containing batch results
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Determine file format and load extensions
        extension_list = self._load_extensions_from_file(input_path)

        logger.info(f"Loaded {len(extension_list)} extensions from {input_file}")

        # Generate batch ID from filename
        batch_id = f"batch_{input_path.stem}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        return self.process_batch(
            extension_list, batch_id=batch_id, parallel=parallel, max_workers=max_workers
        )

    def _load_extensions_from_file(self, input_path: Path) -> List[str]:
        """
        Load extension list from file based on format (TXT, CSV, JSON).

        Args:
            input_path: Path to input file

        Returns:
            List of extension URLs/IDs/paths
        """
        suffix = input_path.suffix.lower()

        if suffix == '.json':
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Handle array of strings or objects
                    extensions = []
                    for item in data:
                        if isinstance(item, str):
                            extensions.append(item)
                        elif isinstance(item, dict):
                            # Try common field names
                            ext = item.get('url') or item.get('id') or item.get('path')
                            if ext:
                                extensions.append(ext)
                    return extensions
                else:
                    raise ValueError("JSON file must contain an array")

        elif suffix == '.csv':
            extensions = []
            with open(input_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Try common column names
                    ext = row.get('url') or row.get('id') or row.get('path') or row.get('extension')
                    if ext:
                        extensions.append(ext.strip())
            return extensions

        else:
            # Default to TXT format (one per line)
            with open(input_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]

    def _process_sequential(self, extension_list: List[str], batch_id: str) -> List[Dict]:
        """Process extensions sequentially with progress tracking."""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Processing {len(extension_list)} extensions...",
                total=len(extension_list)
            )
            
            for idx, extension_path in enumerate(extension_list, 1):
                progress.update(task, description=f"[cyan]Processing: {extension_path[:50]}...")
                result = self._analyze_single_extension(extension_path, batch_id, idx)
                results.append(result)
                progress.advance(task)
                
        return results

    def _process_parallel(
        self, extension_list: List[str], batch_id: str, max_workers: int
    ) -> List[Dict]:
        """Process extensions in parallel with progress tracking."""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Processing {len(extension_list)} extensions (parallel)...",
                total=len(extension_list)
            )
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_ext = {
                    executor.submit(
                        self._analyze_single_extension, ext_path, batch_id, idx
                    ): (idx, ext_path)
                    for idx, ext_path in enumerate(extension_list, 1)
                }

                # Collect results as they complete
                for future in as_completed(future_to_ext):
                    idx, ext_path = future_to_ext[future]
                    try:
                        result = future.result()
                        results.append(result)
                        progress.update(
                            task,
                            description=f"[cyan]Completed: {ext_path[:50]}..."
                        )
                        progress.advance(task)
                    except Exception as e:
                        logger.error(f"Error processing {ext_path}: {e}")
                        results.append(
                            {
                                "extension_path": ext_path,
                                "status": "failed",
                                "error": str(e),
                                "index": idx,
                            }
                        )
                        progress.advance(task)

        # Sort results by index to maintain order
        results.sort(key=lambda x: x.get("index", 0))
        return results

    def _analyze_single_extension(
        self, extension_path: str, batch_id: str, index: int
    ) -> Dict:
        """
        Analyze a single extension using the workflow graph.

        Args:
            extension_path: Extension URL, ID, or file path
            batch_id: Batch identifier
            index: Extension index in batch

        Returns:
            Dict containing analysis results
        """
        workflow_id = f"{batch_id}_ext_{index}"

        try:
            # Initialize workflow state
            initial_state: WorkflowState = {
                "workflow_id": workflow_id,
                "chrome_extension_path": extension_path,
                "extension_dir": None,
                "downloaded_crx_path": None,
                "extension_metadata": None,
                "manifest_data": None,
                "analysis_results": None,
                "executive_summary": None,
                "extracted_files": None,
                "status": WorkflowStatus.PENDING,
                "start_time": datetime.utcnow().isoformat(),
                "end_time": None,
                "error": None,
            }

            # Run workflow
            final_state = self.workflow_graph.invoke(initial_state)

            # Extract relevant results
            result = {
                "extension_path": extension_path,
                "workflow_id": workflow_id,
                "status": final_state.get("status", "unknown"),
                "index": index,
                "manifest": final_state.get("manifest_data"),
                "metadata": final_state.get("extension_metadata"),
                "analysis_results": final_state.get("analysis_results"),
                "executive_summary": final_state.get("executive_summary"),
                "error": final_state.get("error"),
                "start_time": final_state.get("start_time"),
                "end_time": final_state.get("end_time"),
            }

            return result

        except Exception as e:
            logger.error(f"Error analyzing {extension_path}: {e}", exc_info=True)
            return {
                "extension_path": extension_path,
                "workflow_id": workflow_id,
                "status": "failed",
                "index": index,
                "error": str(e),
                "start_time": datetime.utcnow().isoformat(),
                "end_time": datetime.utcnow().isoformat(),
            }

    def _save_batch_state(self, batch_id: str, batch_state: Dict) -> None:
        """Save batch state to JSON file."""
        state_file = self.output_dir / f"{batch_id}_state.json"
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(batch_state, f, indent=2, default=str)

    def generate_batch_report(self, results: Dict, batch_id: str) -> Path:
        """
        Generate a comprehensive batch report.

        Args:
            results: Batch results dictionary
            batch_id: Batch identifier

        Returns:
            Path to the generated report file
        """
        report_path = self.output_dir / f"{batch_id}_report.json"

        # Calculate statistics
        total = results.get("total_extensions", 0)
        completed = results.get("completed", 0)
        failed = results.get("failed", 0)
        success_rate = (completed / total * 100) if total > 0 else 0

        # Aggregate findings
        all_findings = []
        high_risk_extensions = []
        critical_findings_count = 0

        for result in results.get("results", []):
            if result.get("status") == "completed":
                analysis = result.get("analysis_results", {})
                ext_path = result.get("extension_path", "unknown")

                # Collect SAST findings
                sast = analysis.get("javascript_analysis", {})
                if sast and sast.get("findings"):
                    for finding in sast["findings"]:
                        finding["extension"] = ext_path
                        all_findings.append(finding)
                        if finding.get("severity") == "CRITICAL":
                            critical_findings_count += 1

                # Identify high-risk extensions
                summary = result.get("executive_summary", {})
                if summary and summary.get("overall_risk_level") in ["HIGH", "CRITICAL"]:
                    high_risk_extensions.append(
                        {
                            "extension": ext_path,
                            "risk_level": summary.get("overall_risk_level"),
                            "risk_score": summary.get("risk_score"),
                        }
                    )

        # Build comprehensive report
        report = {
            "batch_id": batch_id,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_extensions": total,
                "completed": completed,
                "failed": failed,
                "success_rate": round(success_rate, 2),
                "total_findings": len(all_findings),
                "critical_findings": critical_findings_count,
                "high_risk_extensions": len(high_risk_extensions),
            },
            "high_risk_extensions": high_risk_extensions,
            "findings_by_severity": self._group_findings_by_severity(all_findings),
            "findings_by_category": self._group_findings_by_category(all_findings),
            "detailed_results": results.get("results", []),
        }

        # Save report
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Batch report generated: {report_path}")
        return report_path

    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict:
        """Group findings by severity level."""
        severity_groups = {"CRITICAL": [], "ERROR": [], "WARNING": [], "INFO": []}
        for finding in findings:
            severity = finding.get("severity", "INFO")
            if severity in severity_groups:
                severity_groups[severity].append(finding)
        return {k: len(v) for k, v in severity_groups.items()}

    def _group_findings_by_category(self, findings: List[Dict]) -> Dict:
        """Group findings by category."""
        category_groups = {}
        for finding in findings:
            category = finding.get("category", "unknown")
            if category not in category_groups:
                category_groups[category] = []
            category_groups[category].append(finding)
        return {k: len(v) for k, v in category_groups.items()}

    def get_batch_status(self, batch_id: str) -> Optional[Dict]:
        """
        Get the current status of a batch.

        Args:
            batch_id: Batch identifier

        Returns:
            Dict containing batch status or None if not found
        """
        state_file = self.output_dir / f"{batch_id}_state.json"
        if not state_file.exists():
            return None

        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_batch_results(self, batch_id: str) -> Optional[Dict]:
        """
        Get the full results of a completed batch.

        Args:
            batch_id: Batch identifier

        Returns:
            Dict containing batch results or None if not found
        """
        report_file = self.output_dir / f"{batch_id}_report.json"
        if not report_file.exists():
            return None

        with open(report_file, "r", encoding="utf-8") as f:
            return json.load(f)

# Made with Bob

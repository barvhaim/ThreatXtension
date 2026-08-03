"""
FastAPI Backend for ThreatXtension

Provides REST API endpoints for the frontend to trigger extension analysis
and retrieve results.
"""

import os
import json
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import shutil

from threatxtension.core.report_generator import ReportGenerator

from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowState, WorkflowStatus
from threatxtension.api.database import db

logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    """Request model for triggering a scan."""

    url: str
    force: bool = False


class ScanStatusResponse(BaseModel):
    """Response model for scan status."""

    scanned: bool
    status: Optional[str] = None
    extension_id: Optional[str] = None
    error: Optional[str] = None


class FileContentResponse(BaseModel):
    """Response model for file content."""

    content: str
    file_path: str


class FileListResponse(BaseModel):
    """Response model for file list."""

    files: list[str]


app = FastAPI(
    title="ThreatXtension API",
    description="REST API for Chrome extension security analysis",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8007",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"

scan_results: Dict[str, Dict[str, Any]] = {}
scan_status: Dict[str, str] = {}


def load_existing_results():
    """Load existing scan results from database into memory cache."""
    history = db.get_scan_history(limit=100)
    for item in history:
        ext_id = item.get("extension_id")
        if ext_id:
            scan_status[ext_id] = item.get("status", "completed")


load_existing_results()

RESULTS_DIR = Path("extensions_storage")
RESULTS_DIR.mkdir(exist_ok=True)


def extract_extension_id(url: str) -> Optional[str]:
    """
    Extract extension ID from Chrome Web Store URL or validate standalone ID.

    Args:
        url: Chrome Web Store URL or 32-character extension ID

    Returns:
        Extension ID if valid, None otherwise
    """
    # Check if input is already an extension ID (32 lowercase letters a-p)
    if re.match(r"^[a-p]{32}$", url.strip().lower()):
        return url.strip().lower()

    match = re.search(r"/detail/(?:[^/]+/)?([a-z]{32})", url)
    return match.group(1) if match else None


async def run_analysis_workflow(url: str, extension_id: str):
    """Run the analysis workflow in the background."""
    try:
        scan_status[extension_id] = "running"

        graph = build_graph()

        initial_state: WorkflowState = {
            "workflow_id": extension_id,
            "chrome_extension_path": url,
            "extension_dir": None,
            "downloaded_crx_path": None,
            "extension_metadata": None,
            "manifest_data": None,
            "analysis_results": None,
            "executive_summary": None,
            "extracted_files": None,
            # Web UI file viewer reads the extracted source after analysis.
            "keep_extracted": True,
            "status": WorkflowStatus.PENDING,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "error": None,
        }

        final_state = await graph.ainvoke(initial_state)

        if (
            final_state["status"] == WorkflowStatus.COMPLETED
            or final_state["status"] == "completed"
        ):
            analysis_results = final_state.get("analysis_results", {}) or {}

            metadata = final_state.get("extension_metadata") or {}
            manifest = final_state.get("manifest_data") or {}
            extension_name = (
                metadata.get("title")
                or metadata.get("name")
                or manifest.get("name")
                or extension_id
            )

            extracted_files = final_state.get("extracted_files")
            if extracted_files is None:
                extracted_files = []

            scan_results[extension_id] = {
                "extension_id": extension_id,
                "extension_name": extension_name,
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "metadata": metadata,
                "chromeStatsMetadata": (
                    metadata.get("chrome_stats")
                    if metadata and "chrome_stats" in metadata
                    else (
                        metadata
                        if metadata
                        and "download_source" in metadata
                        and metadata.get("download_source") == "chrome-stats.com"
                        else None
                    )
                ),
                "manifest": manifest,
                "permissions_analysis": analysis_results.get("permissions_analysis") or {},
                "sast_results": analysis_results.get("javascript_analysis") or {},
                "webstore_analysis": analysis_results.get("webstore_analysis") or {},
                "virustotal_analysis": analysis_results.get("virustotal_analysis") or {},
                "entropy_analysis": analysis_results.get("entropy_analysis") or {},
                "summary": final_state.get("executive_summary") or {},
                "extracted_path": final_state.get("extension_dir"),
                "extracted_files": extracted_files,
                "overall_security_score": calculate_security_score(final_state),
                "total_findings": count_total_findings(final_state),
                "risk_distribution": calculate_risk_distribution(final_state),
                "overall_risk": determine_overall_risk(final_state),
                "total_risk_score": calculate_total_risk_score(final_state),
            }
            scan_status[extension_id] = "completed"

            db.save_scan_result(scan_results[extension_id])

            result_file = RESULTS_DIR / f"{extension_id}_results.json"
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(scan_results[extension_id], f, indent=2)
        else:
            scan_status[extension_id] = "failed"
            scan_results[extension_id] = {
                "extension_id": extension_id,
                "url": url,
                "status": "failed",
                "error": final_state.get("error", "Unknown error"),
            }

    except Exception as e:
        scan_status[extension_id] = "failed"
        scan_results[extension_id] = {
            "extension_id": extension_id,
            "url": url,
            "status": "failed",
            "error": str(e),
        }


def get_extracted_files(extracted_path: Optional[str]) -> list[str]:
    """Get list of extracted files from the extension."""
    if not extracted_path or not os.path.exists(extracted_path):
        return []

    files = []
    for root, _, filenames in os.walk(extracted_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, extracted_path)
            files.append(rel_path)

    return files


def _score_from_executive_summary(state: WorkflowState) -> Optional[int]:
    """
    Read the SecurityScorer result the summary node stamped onto the state.

    Returns None when the state has no usable score, so the caller can fall back to its
    own calculation. `SummaryGenerator` writes this on both the LLM-success and
    LLM-failure paths, so a failed LLM call still yields the deterministic score.
    """
    summary = state.get("executive_summary") or {}
    if not isinstance(summary, dict):
        return None

    score = summary.get("security_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None

    return max(0, min(100, int(score)))


def _risk_level_from_executive_summary(state: WorkflowState) -> Optional[str]:
    """Read the SecurityScorer risk level, so the band matches the score it came from."""
    summary = state.get("executive_summary") or {}
    if not isinstance(summary, dict):
        return None

    level = summary.get("overall_risk_level")
    if not isinstance(level, str):
        return None

    level = level.strip().lower()
    return level if level in {"low", "medium", "high", "critical"} else None


def calculate_security_score(state: WorkflowState) -> int:
    """
    Return the authoritative risk score for a completed scan (0-100, higher = worse).

    `SecurityScorer` owns the scoring model, so this defers to the score the workflow
    already stamped onto the executive summary. It used to reimplement scoring with its
    own weights, which meant the dashboard and the summary reported different numbers
    for the same extension (e.g. 41 vs 50).

    The local weighted calculation below is retained only as a fallback for states that
    never reached the summary node — `SummaryGenerator.generate()` returns None when the
    analysis results or manifest are empty, and callers may score a partial state.

    Returns:
        int: Risk score from 0 (lowest risk) to 100 (most dangerous)
    """
    analysis_results = state.get("analysis_results", {}) or {}
    manifest = state.get("manifest_data", {}) or {}

    scored = _score_from_executive_summary(state)
    if scored is not None:
        return scored

    # Component 1: SAST Analysis (50 points max risk) - INCREASED from 40
    sast_score = 0
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        high_count = 0
        medium_count = 0

        for findings_list in sast_findings.values():
            for finding in findings_list:
                severity = finding.get("extra", {}).get("severity", "INFO").upper()
                if severity in ("CRITICAL", "ERROR", "HIGH"):
                    sast_score += 10
                    high_count += 1
                elif severity in ("MEDIUM", "WARNING"):
                    sast_score += 3
                    medium_count += 1
                elif severity == "LOW":
                    sast_score += 1

        # Bonus penalty for multiple critical findings (indicates systematic issues)
        if high_count >= 10:
            sast_score += 20
        elif high_count >= 5:
            sast_score += 10

    sast_score = min(50, sast_score)

    # Component 2: Permissions Analysis (35 points max risk) - INCREASED from 30
    permissions_score = 0
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    _ = len(permissions_details)  # total_permissions - kept for potential future use
    unreasonable_count = 0
    high_risk_perms = 0

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        risk = perm_analysis.get("risk_level", "").lower()

        if not is_reasonable:
            unreasonable_count += 1
            if risk == "high":
                high_risk_perms += 1
                permissions_score += 8
            elif risk == "medium":
                permissions_score += 4
            else:
                permissions_score += 2

    if unreasonable_count >= 10:
        permissions_score += 15
    elif unreasonable_count >= 5:
        permissions_score += 8

    permissions_score = min(35, permissions_score)

    # Component 3: Webstore Trust Score (10 points max risk) - REDUCED from 20
    webstore_score = 0
    _ = analysis_results.get("webstore_analysis", {})  # webstore_analysis - for future use
    metadata = state.get("extension_metadata", {}) or {}

    rating = metadata.get("rating")
    if rating:
        try:
            rating_val = float(rating)
            if rating_val >= 4.5:
                webstore_score += 0
            elif rating_val >= 4.0:
                webstore_score += 1
            elif rating_val >= 3.0:
                webstore_score += 3
            else:
                webstore_score += 5
        except (ValueError, TypeError):
            webstore_score += 2
    else:
        webstore_score += 2

    users = metadata.get("user_count", metadata.get("users", "0"))
    try:
        user_count = int(str(users).replace(",", "").replace("+", ""))
        if user_count >= 1000000:
            webstore_score += 0
        elif user_count >= 100000:
            webstore_score += 1
        elif user_count >= 10000:
            webstore_score += 2
        else:
            webstore_score += 4
    except (ValueError, TypeError):
        webstore_score += 2

    webstore_score = min(10, webstore_score)

    # Component 4: Manifest Quality (5 points max risk) - REDUCED from 10
    manifest_score = 0

    if not manifest.get("name") or manifest.get("name", "").startswith("__MSG_"):
        manifest_score += 2
    if not manifest.get("description") or manifest.get("description", "").startswith("__MSG_"):
        manifest_score += 1

    if not manifest.get("content_security_policy"):
        manifest_score += 1

    if not manifest.get("update_url"):
        manifest_score += 1

    manifest_score = min(5, manifest_score)

    # Component 5: VirusTotal Threat Intelligence (40 points max risk)
    virustotal_score = 0
    vt_analysis = analysis_results.get("virustotal_analysis", {})
    if vt_analysis and vt_analysis.get("enabled", True):
        summary = vt_analysis.get("summary", {})
        threat_level = summary.get("threat_level", "").lower()

        if threat_level == "malicious":
            virustotal_score += 40
        elif threat_level == "suspicious":
            virustotal_score += 25

        detected_families = summary.get("detected_families", [])
        if detected_families:
            virustotal_score += min(20, len(detected_families) * 5)

        total_malicious = vt_analysis.get("total_malicious", 0)
        total_suspicious = vt_analysis.get("total_suspicious", 0)

        if total_malicious > 0:
            virustotal_score += min(30, total_malicious * 3)
        elif total_suspicious > 0:
            virustotal_score += min(15, total_suspicious * 2)

    virustotal_score = min(40, virustotal_score)

    # Component 6: Entropy/Obfuscation Analysis (30 points max risk)
    entropy_score = 0
    entropy_analysis = analysis_results.get("entropy_analysis", {})
    if entropy_analysis:
        summary = entropy_analysis.get("summary", {})
        overall_risk = summary.get("overall_risk", "").lower()

        if overall_risk == "high":
            entropy_score += 25
        elif overall_risk == "medium":
            entropy_score += 15

        high_entropy_files = summary.get("high_entropy_files", [])
        if high_entropy_files:
            entropy_score += min(20, len(high_entropy_files) * 5)

        obfuscated_files = entropy_analysis.get("obfuscated_files", 0)
        if obfuscated_files > 0:
            entropy_score += min(15, obfuscated_files * 3)

    entropy_score = min(30, entropy_score)

    # Component 7: Chrome Stats behavioral risk (20 points max risk)
    chromestats_score = 0
    chromestats_analysis = analysis_results.get("chromestats_analysis", {})
    if chromestats_analysis:
        overall_risk = chromestats_analysis.get("overall_risk_level", "").lower()
        if overall_risk == "critical":
            chromestats_score += 20
        elif overall_risk == "high":
            chromestats_score += 15
        elif overall_risk == "medium":
            chromestats_score += 8

        api_risk = chromestats_analysis.get("api_risk_analysis", {})
        if api_risk.get("has_api_risk_data"):
            try:
                risk_impact = int(api_risk.get("risk_impact") or 0)
                risk_likelihood = int(api_risk.get("risk_likelihood") or 0)
            except (TypeError, ValueError):
                risk_impact = 0
                risk_likelihood = 0
            chromestats_score += min(10, risk_impact + risk_likelihood)

        risk_indicators = chromestats_analysis.get("risk_indicators", [])
        chromestats_score += min(10, len(risk_indicators) * 2)

    chromestats_score = min(20, chromestats_score)

    # Total possible: 50 + 35 + 10 + 5 + 40 + 30 + 20 = 190 points
    risk_score = (
        sast_score
        + permissions_score
        + webstore_score
        + manifest_score
        + virustotal_score
        + entropy_score
        + chromestats_score
    )

    # Cap at 100. Higher means more dangerous.
    risk_score = min(100, risk_score)
    return max(0, risk_score)


def _is_within_directory(base_dir: str, target_path: str) -> bool:
    """Return True when target_path resolves inside base_dir."""
    try:
        base_abs = os.path.abspath(base_dir)
        target_abs = os.path.abspath(target_path)
        return os.path.commonpath([base_abs, target_abs]) == base_abs
    except ValueError:
        return False


def count_total_findings(state: WorkflowState) -> int:
    """Count total security findings including unreasonable permissions."""
    analysis_results = state.get("analysis_results", {}) or {}

    javascript_analysis = analysis_results.get("javascript_analysis", {})
    total = 0
    if javascript_analysis:
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            if findings_list is not None:
                total += len(findings_list)

    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        if not is_reasonable:
            total += 1

    return total


def calculate_risk_distribution(state: WorkflowState) -> Dict[str, int]:
    """Calculate distribution of risk levels."""
    distribution = {"high": 0, "medium": 0, "low": 0}

    analysis_results = state.get("analysis_results", {}) or {}

    javascript_analysis = analysis_results.get("javascript_analysis", {})
    js_analysis = []
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            if findings_list is not None:
                js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
        js_analysis = javascript_analysis

    for finding in js_analysis:
        risk_level = finding.get("extra", {}).get("severity", "INFO").lower()
        if risk_level in ("critical", "high"):
            distribution["high"] += 1
        elif risk_level in ("error", "medium"):
            distribution["medium"] += 1
        else:
            distribution["low"] += 1

    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        risk = perm_analysis.get("risk_level", "").lower()

        if not is_reasonable:
            if risk == "high":
                distribution["high"] += 1
            elif risk == "low":
                distribution["low"] += 1
            else:
                distribution["medium"] += 1

    return distribution


def determine_overall_risk(state: WorkflowState) -> str:
    """
    Determine overall risk level, preferring the level SecurityScorer already assigned.

    Falls back to banding the score locally for states that never reached the summary
    node. The thresholds mirror `SecurityScorer._get_risk_level()`.
    """
    level = _risk_level_from_executive_summary(state)
    if level is not None:
        return level

    score = calculate_security_score(state)

    if score >= 61:
        return "critical"
    if score >= 36:
        return "high"
    if score >= 16:
        return "medium"
    return "low"


def calculate_total_risk_score(state: WorkflowState) -> int:
    """Calculate total risk score."""
    analysis_results = state.get("analysis_results", {}) or {}
    javascript_analysis = analysis_results.get("javascript_analysis", {})

    js_analysis = []
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
        js_analysis = javascript_analysis

    total_score = 0
    severity_scores = {"CRITICAL": 10, "HIGH": 8, "ERROR": 5, "MEDIUM": 5, "WARNING": 1, "INFO": 0}

    for finding in js_analysis:
        severity = finding.get("extra", {}).get("severity", "INFO")
        total_score += severity_scores.get(severity, 0)

    return total_score


@app.get("/")
async def root():
    """Root endpoint - serves frontend or API info."""
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)
    return {"name": "ThreatXtension API", "version": "1.0.0", "status": "running"}


@app.post("/api/scan/trigger")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger a new extension scan.

    Args:
        request: Scan request containing the extension URL
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    url = request.url
    force = request.force
    extension_id = extract_extension_id(url)

    if not extension_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid input. Please provide a Chrome Web Store URL or extension ID (32-character string)",
        )

    if extension_id in scan_status and scan_status[extension_id] == "running":
        return {
            "message": "Scan already in progress",
            "extension_id": extension_id,
            "status": "running",
        }

    if not force:
        existing_result = db.get_scan_result(extension_id)
        if existing_result:
            return {
                "message": "Extension already scanned (use force=true to re-scan)",
                "extension_id": extension_id,
                "status": "completed",
                "already_scanned": True,
            }

    if force and extension_id in scan_status:
        del scan_status[extension_id]
    if force and extension_id in scan_results:
        del scan_results[extension_id]

    background_tasks.add_task(run_analysis_workflow, url, extension_id)

    return {
        "message": "Scan triggered successfully" + (" (forced re-scan)" if force else ""),
        "extension_id": extension_id,
        "status": "running",
        "forced": force,
    }


@app.post("/api/scan/upload")
async def upload_and_scan(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Upload a CRX/ZIP file and trigger analysis.

    Args:
        file: Uploaded CRX or ZIP file
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    filename_lower = file.filename.lower()
    if not (filename_lower.endswith(".crx") or filename_lower.endswith(".zip")):
        raise HTTPException(
            status_code=400, detail="Invalid file type. Only .crx and .zip files are supported"
        )

    max_size = 100 * 1024 * 1024  # 100MB
    file_content = await file.read()
    if len(file_content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {max_size / (1024*1024):.0f}MB",
        )

    import uuid

    extension_id = str(uuid.uuid4())

    safe_filename = Path(file.filename).name
    file_path = RESULTS_DIR / f"{extension_id}_{safe_filename}"

    try:
        with open(file_path, "wb") as buffer:
            buffer.write(file_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}") from e

    background_tasks.add_task(run_analysis_workflow, str(file_path), extension_id)

    return {
        "message": "File uploaded and scan triggered successfully",
        "extension_id": extension_id,
        "filename": safe_filename,
        "status": "running",
    }


@app.get("/api/scan/status/{extension_id}")
async def get_scan_status(extension_id: str) -> ScanStatusResponse:
    """
    Get the status of a scan.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Scan status information
    """
    status = scan_status.get(extension_id)

    if not status:
        return ScanStatusResponse(scanned=False)

    result = scan_results.get(extension_id, {})

    return ScanStatusResponse(
        scanned=status == "completed",
        status=status,
        extension_id=extension_id,
        error=result.get("error"),
    )


@app.get("/api/scan/results/{extension_id}")
async def get_scan_results(extension_id: str):
    """
    Get the results of a completed scan.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Complete scan results
    """
    if extension_id in scan_results:
        return scan_results[extension_id]

    results = db.get_scan_result(extension_id)
    if results:
        metadata = results.get("metadata", {})

        formatted_results = {
            "extension_id": results.get("extension_id"),
            "extension_name": results.get("extension_name"),
            "url": results.get("url"),
            "timestamp": results.get("timestamp"),
            "status": results.get("status"),
            "metadata": metadata,
            "chromeStatsMetadata": (
                metadata.get("chrome_stats")
                if metadata and "chrome_stats" in metadata
                else (
                    metadata
                    if metadata
                    and "download_source" in metadata
                    and metadata.get("download_source") == "chrome-stats.com"
                    else None
                )
            ),
            "manifest": results.get("manifest", {}),
            "permissions_analysis": results.get("permissions_analysis", {}),
            "sast_results": results.get("sast_results", {}),
            "webstore_analysis": results.get("webstore_analysis", {}),
            "summary": results.get("summary", {}),
            "extracted_path": results.get("extracted_path"),
            "extracted_files": results.get("extracted_files", []),
            "overall_security_score": results.get("security_score", 0),
            "total_findings": results.get("total_findings", 0),
            "risk_distribution": {
                "high": results.get("high_risk_count", 0),
                "medium": results.get("medium_risk_count", 0),
                "low": results.get("low_risk_count", 0),
            },
            "overall_risk": results.get("risk_level", "unknown"),
            "total_risk_score": results.get("total_findings", 0),
        }
        scan_results[extension_id] = formatted_results
        return formatted_results

    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    if result_file.exists():
        with open(result_file, "r", encoding="utf-8") as f:
            results = json.load(f)
            scan_results[extension_id] = results
            return results

    raise HTTPException(status_code=404, detail="Scan results not found")


@app.get("/api/scan/report/{extension_id}")
async def generate_pdf_report(extension_id: str) -> Response:
    """
    Generate a PDF security report for an analyzed extension.

    Args:
        extension_id: Chrome extension ID

    Returns:
        PDF file as downloadable response
    """
    results = scan_results.get(extension_id)

    if not results:
        results = db.get_scan_result(extension_id)
        if results:
            scan_results[extension_id] = results

    if not results:
        results_file = RESULTS_DIR / f"{extension_id}_results.json"
        if results_file.exists():
            with open(results_file, "r", encoding="utf-8") as f:
                results = json.load(f)
                scan_results[extension_id] = results

    if not results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    try:
        report_generator = ReportGenerator()
        if not report_generator.enabled:
            raise HTTPException(
                status_code=503, detail="PDF generation is disabled. Install weasyprint to enable."
            )

        pdf_bytes = report_generator.generate_pdf(results)

        extension_name = results.get(
            "extension_name", results.get("metadata", {}).get("title", extension_id)
        )
        safe_name = "".join(c for c in extension_name if c.isalnum() or c in " -_")[:50]
        filename = f"ThreatXtension_Report_{safe_name}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


@app.get("/api/scan/files/{extension_id}")
async def get_file_list(extension_id: str) -> FileListResponse:
    """
    Get list of files in the extracted extension.

    Args:
        extension_id: Chrome extension ID

    Returns:
        List of file paths
    """
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")

    extracted_path = results.get("extracted_path")
    if not extracted_path or not os.path.exists(extracted_path):
        raise HTTPException(status_code=404, detail="Extracted files not found")

    files = get_extracted_files(extracted_path)
    return FileListResponse(files=files)


@app.get("/api/scan/file/{extension_id}/{file_path:path}")
async def get_file_content(extension_id: str, file_path: str) -> FileContentResponse:
    """
    Get content of a specific file from the extracted extension.

    Args:
        extension_id: Chrome extension ID
        file_path: Relative path to the file

    Returns:
        File content
    """
    results = scan_results.get(extension_id)
    if not results:
        raise HTTPException(status_code=404, detail="Extension not found")

    extracted_path = results.get("extracted_path")
    if not extracted_path:
        raise HTTPException(status_code=404, detail="Extracted files not found")

    full_path = os.path.join(extracted_path, file_path)

    # Security check: ensure path is within extracted directory
    if not _is_within_directory(extracted_path, full_path):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        return FileContentResponse(content=content, file_path=file_path)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Cannot read binary file") from exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}") from e


@app.get("/api/statistics")
async def get_statistics():
    """
    Get aggregated statistics.

    Returns:
        Statistics including total scans, high risk count, etc.
    """
    stats = db.get_statistics()
    risk_dist = db.get_risk_distribution()

    return {
        "total_scans": stats.get("total_scans", 0),
        "high_risk_extensions": stats.get("high_risk_extensions", 0),
        "total_files_analyzed": stats.get("total_files_analyzed", 0),
        "total_vulnerabilities": stats.get("total_vulnerabilities", 0),
        "avg_security_score": stats.get("avg_security_score", 0),
        "risk_distribution": risk_dist,
    }


@app.get("/api/history")
async def get_history(limit: int = 50):
    """
    Get scan history.

    Args:
        limit: Maximum number of results to return

    Returns:
        List of scan history items
    """
    history = db.get_scan_history(limit=limit)
    return {"history": history, "total": len(history)}


@app.get("/api/recent")
async def get_recent_scans(limit: int = 10):
    """
    Get recent scans with summary info.

    Args:
        limit: Maximum number of results to return

    Returns:
        List of recent scans
    """
    recent = db.get_recent_scans(limit=limit)
    return {"recent": recent}


@app.delete("/api/scan/{extension_id}")
async def delete_scan(extension_id: str):
    """
    Delete a scan result.

    Args:
        extension_id: Chrome extension ID

    Returns:
        Deletion confirmation
    """
    success = db.delete_scan_result(extension_id)

    if success:
        scan_results.pop(extension_id, None)
        scan_status.pop(extension_id, None)

        return {"message": "Scan deleted successfully", "extension_id": extension_id}

    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/api/clear")
async def clear_all_scans():
    """
    Clear all scan results.

    Returns:
        Confirmation message
    """
    success = db.clear_all_results()

    if success:
        scan_results.clear()
        scan_status.clear()
        return {"message": "All scans cleared successfully"}

    raise HTTPException(status_code=500, detail="Failed to clear scans")


@app.post("/api/analyze/file")
async def analyze_file_with_ai(
    file_content: str = Form(..., description="File content to analyze"),
    file_name: str = Form(..., description="Name of the file"),
    file_type: str = Form(..., description="Type/extension of the file"),
    provider: str = Form(default="auto", description="LLM provider to use"),
):
    """
    Analyze a file using AI/LLM for security insights.

    This endpoint provides AI-powered security analysis of individual files
    from Chrome extensions using configured LLM providers.

    Args:
        file_content: The actual content of the file to analyze
        file_name: Name of the file (e.g., "background.js")
        file_type: File type/extension (e.g., "js", "json")
        provider: LLM provider to use ("auto", "watsonx", "openai", "ollama", etc.)

    Returns:
        AI analysis results including risk score, findings, and recommendations
    """
    try:
        from threatxtension.llm.clients import get_chat_llm_client
        from langchain_core.prompts import PromptTemplate
        from langchain_core.output_parsers import JsonOutputParser

        if provider == "auto":
            llm_provider = os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
        else:
            llm_provider = provider

        prompt_template = """You are a security expert analyzing a Chrome extension file for potential security vulnerabilities and malicious behavior.

File Name: {file_name}
File Type: {file_type}

File Content:
```
{file_content}
```

Analyze this file for security issues including:
1. Malicious code patterns (data exfiltration, credential theft, etc.)
2. Suspicious API usage
3. Obfuscation or encoding techniques
4. Privacy violations
5. Dangerous permissions or capabilities

Provide your analysis in the following JSON format:
{{
    "riskScore": <number 1-10, where 10 is highest risk>,
    "severity": "<Low|Medium|High>",
    "confidence": "<Low|Medium|High>",
    "analysis": "<detailed security analysis text>",
    "findings": [
        "<finding 1>",
        "<finding 2>"
    ],
    "recommendations": [
        "<recommendation 1>",
        "<recommendation 2>"
    ]
}}

Focus on actionable security insights. Be specific about any suspicious patterns found."""

        prompt = PromptTemplate(
            input_variables=["file_name", "file_type", "file_content"], template=prompt_template
        )

        llm = get_chat_llm_client(
            model_name=llm_provider,
            model_parameters={
                "temperature": 0.1,
                "max_tokens": 2048,
            },
        )

        truncated_content = file_content[:5000]
        if len(file_content) > 5000:
            truncated_content += "\n\n... (content truncated for analysis)"

        try:
            chain = prompt | llm | JsonOutputParser()

            result = chain.invoke(
                {"file_name": file_name, "file_type": file_type, "file_content": truncated_content}
            )
        except Exception as parse_error:
            logger.warning(f"JSON parsing failed, trying raw output: {parse_error}")
            chain_raw = prompt | llm

            raw_result = chain_raw.invoke(
                {"file_name": file_name, "file_type": file_type, "file_content": truncated_content}
            )

            import re

            raw_text = raw_result.content if hasattr(raw_result, "content") else str(raw_result)

            json_match = re.search(r"\{[\s\S]*\}", raw_text)
            if json_match:
                try:
                    result = json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    result = {
                        "riskScore": 5,
                        "severity": "Medium",
                        "confidence": "Low",
                        "analysis": raw_text[:500],
                        "findings": ["Unable to parse detailed analysis"],
                        "recommendations": ["Manual review recommended"],
                    }
            else:
                result = {
                    "riskScore": 5,
                    "severity": "Medium",
                    "confidence": "Low",
                    "analysis": raw_text[:500],
                    "findings": ["Unable to parse detailed analysis"],
                    "recommendations": ["Manual review recommended"],
                }

        result["metadata"] = {
            "model": llm_provider,
            "deployment": "Backend API",
            "file_size": len(file_content),
            "truncated": len(file_content) > 5000,
            "timestamp": datetime.now().isoformat(),
        }

        return {"success": True, "data": result}

    except ImportError as e:
        raise HTTPException(
            status_code=503, detail=f"LLM dependencies not available: {str(e)}"
        ) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}") from e


@app.post("/api/analyze/generate-sast-signature")
async def generate_sast_signature(
    file_content: str = Form(...), file_name: str = Form(...), provider: str = Form("auto")
):
    """
    Generate SAST signatures (Semgrep rules) from file content using AI.

    This endpoint analyzes the file and creates multiple custom Semgrep rule patterns
    based on the actual code patterns found in the file.
    """
    try:
        from threatxtension.llm.clients import get_chat_llm_client

        llm_client = get_chat_llm_client()

        content_preview = file_content[:3000] if len(file_content) > 3000 else file_content

        prompt = f"""You are a security expert analyzing JavaScript code to create Semgrep SAST rules.

Analyze this {file_name} file and generate 3-5 Semgrep rules based on ACTUAL security patterns found in the code.

File Content:
```javascript
{content_preview}
```

For each security pattern you find in the code, create a Semgrep rule. Focus on:
1. Actual dangerous function calls present in the code (eval, innerHTML, document.write, etc.)
2. Network requests (fetch, XMLHttpRequest, WebSocket)
3. Data storage operations (localStorage, sessionStorage, cookies)
4. DOM manipulation patterns
5. Authentication/authorization code

Return a JSON array of rules in this format:
[
  {{
    "rule_id": "descriptive-name-based-on-pattern",
    "pattern": "actual semgrep pattern matching code in file",
    "message": "Clear description of security issue",
    "severity": "ERROR|WARNING|INFO",
    "languages": ["javascript"],
    "metadata": {{
      "category": "security",
      "cwe": "CWE-XXX",
      "confidence": "HIGH|MEDIUM|LOW"
    }}
  }}
]

IMPORTANT: Only create rules for patterns that ACTUALLY EXIST in the provided code.
Return ONLY the JSON array, no additional text."""

        response = llm_client.invoke(prompt)

        if hasattr(response, "content"):
            response_text = response.content
        else:
            response_text = str(response)

        try:
            response_text = response_text.strip()
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()

            signatures = json.loads(response_text)

            if not isinstance(signatures, list):
                signatures = [signatures]

        except json.JSONDecodeError:
            signatures = _generate_fallback_signatures(file_content, file_name)

        for sig in signatures:
            sig["provider"] = provider
            sig["generated_at"] = datetime.now().isoformat()
            sig["source_file"] = file_name

        return {
            "success": True,
            "data": signatures[0] if len(signatures) == 1 else signatures,
            "total_signatures": len(signatures),
        }

    except ImportError as e:
        logger.warning(f"LLM not available, using fallback: {e}")
        signatures = _generate_fallback_signatures(file_content, file_name)
        return {
            "success": True,
            "data": signatures[0] if len(signatures) == 1 else signatures,
            "total_signatures": len(signatures),
            "provider": "fallback",
        }
    except Exception as e:
        logger.error(f"SAST signature generation failed: {e}")
        signatures = _generate_fallback_signatures(file_content, file_name)
        return {
            "success": True,
            "data": signatures[0] if len(signatures) == 1 else signatures,
            "total_signatures": len(signatures),
            "provider": "fallback",
            "note": f"Used fallback due to error: {str(e)}",
        }


def _generate_fallback_signatures(file_content: str, file_name: str) -> list:
    """Generate SAST signatures based on actual patterns found in file content."""
    import re

    signatures = []

    patterns_to_check = [
        {
            "regex": r"\beval\s*\(",
            "rule_id": f"custom-eval-usage-{file_name.replace('.', '-')}",
            "pattern": "eval(...)",
            "message": f"Dangerous eval() usage detected in {file_name}",
            "severity": "ERROR",
            "cwe": "CWE-95",
            "example": "eval(userInput)",
        },
        {
            "regex": r"\.innerHTML\s*=",
            "rule_id": f"custom-innerhtml-{file_name.replace('.', '-')}",
            "pattern": "$X.innerHTML = $Y",
            "message": f"Potential XSS via innerHTML in {file_name}",
            "severity": "WARNING",
            "cwe": "CWE-79",
            "example": "element.innerHTML = data",
        },
        {
            "regex": r"\bdocument\.write\s*\(",
            "rule_id": f"custom-document-write-{file_name.replace('.', '-')}",
            "pattern": "document.write(...)",
            "message": f"Dangerous document.write() usage in {file_name}",
            "severity": "WARNING",
            "cwe": "CWE-79",
            "example": "document.write(content)",
        },
        {
            "regex": r"\bfetch\s*\(",
            "rule_id": f"custom-fetch-usage-{file_name.replace('.', '-')}",
            "pattern": "fetch($URL, ...)",
            "message": f"Network request detected in {file_name}",
            "severity": "INFO",
            "cwe": "CWE-200",
            "example": "fetch('https://api.example.com')",
        },
        {
            "regex": r"\bnew\s+XMLHttpRequest\s*\(",
            "rule_id": f"custom-xhr-{file_name.replace('.', '-')}",
            "pattern": "new XMLHttpRequest()",
            "message": f"XMLHttpRequest usage in {file_name}",
            "severity": "INFO",
            "cwe": "CWE-200",
            "example": "new XMLHttpRequest()",
        },
        {
            "regex": r"\blocalStorage\s*[\.\[]",
            "rule_id": f"custom-localstorage-{file_name.replace('.', '-')}",
            "pattern": "localStorage.$METHOD(...)",
            "message": f"localStorage usage in {file_name} - potential data exposure",
            "severity": "INFO",
            "cwe": "CWE-922",
            "example": "localStorage.setItem('key', value)",
        },
        {
            "regex": r"\bsessionStorage\s*[\.\[]",
            "rule_id": f"custom-sessionstorage-{file_name.replace('.', '-')}",
            "pattern": "sessionStorage.$METHOD(...)",
            "message": f"sessionStorage usage in {file_name}",
            "severity": "INFO",
            "cwe": "CWE-922",
            "example": "sessionStorage.getItem('key')",
        },
        {
            "regex": r"\batob\s*\(",
            "rule_id": f"custom-base64-decode-{file_name.replace('.', '-')}",
            "pattern": "atob(...)",
            "message": f"Base64 decoding in {file_name} - check for obfuscation",
            "severity": "INFO",
            "cwe": "CWE-506",
            "example": "atob(encodedData)",
        },
        {
            "regex": r"\bbtoa\s*\(",
            "rule_id": f"custom-base64-encode-{file_name.replace('.', '-')}",
            "pattern": "btoa(...)",
            "message": f"Base64 encoding in {file_name} - check for data exfiltration",
            "severity": "INFO",
            "cwe": "CWE-506",
            "example": "btoa(sensitiveData)",
        },
        {
            "regex": r"\.outerHTML\s*=",
            "rule_id": f"custom-outerhtml-{file_name.replace('.', '-')}",
            "pattern": "$X.outerHTML = $Y",
            "message": f"Potential XSS via outerHTML in {file_name}",
            "severity": "WARNING",
            "cwe": "CWE-79",
            "example": "element.outerHTML = data",
        },
        {
            "regex": r'\bsetTimeout\s*\(\s*["\']',
            "rule_id": f"custom-settimeout-string-{file_name.replace('.', '-')}",
            "pattern": "setTimeout($STR, ...)",
            "message": f"setTimeout with string argument in {file_name} - acts like eval",
            "severity": "WARNING",
            "cwe": "CWE-95",
            "example": "setTimeout('code', 1000)",
        },
        {
            "regex": r'\bsetInterval\s*\(\s*["\']',
            "rule_id": f"custom-setinterval-string-{file_name.replace('.', '-')}",
            "pattern": "setInterval($STR, ...)",
            "message": f"setInterval with string argument in {file_name} - acts like eval",
            "severity": "WARNING",
            "cwe": "CWE-95",
            "example": "setInterval('code', 1000)",
        },
        {
            "regex": r"\bnew\s+Function\s*\(",
            "rule_id": f"custom-function-constructor-{file_name.replace('.', '-')}",
            "pattern": "new Function(...)",
            "message": f"Function constructor usage in {file_name} - acts like eval",
            "severity": "ERROR",
            "cwe": "CWE-95",
            "example": "new Function('return x + y')",
        },
        {
            "regex": r"\bchrome\.runtime\.sendMessage\s*\(",
            "rule_id": f"custom-chrome-messaging-{file_name.replace('.', '-')}",
            "pattern": "chrome.runtime.sendMessage(...)",
            "message": f"Chrome extension messaging in {file_name}",
            "severity": "INFO",
            "cwe": "CWE-200",
            "example": "chrome.runtime.sendMessage({data: value})",
        },
        {
            "regex": r"\bchrome\.storage\.",
            "rule_id": f"custom-chrome-storage-{file_name.replace('.', '-')}",
            "pattern": "chrome.storage.$API.$METHOD(...)",
            "message": f"Chrome storage API usage in {file_name}",
            "severity": "INFO",
            "cwe": "CWE-922",
            "example": "chrome.storage.local.set({key: value})",
        },
    ]

    for pattern_def in patterns_to_check:
        if re.search(pattern_def["regex"], file_content, re.IGNORECASE):
            match = re.search(pattern_def["regex"], file_content, re.IGNORECASE)
            matched_text = match.group(0) if match else pattern_def["example"]

            signatures.append(
                {
                    "rule_id": pattern_def["rule_id"],
                    "pattern": pattern_def["pattern"],
                    "message": pattern_def["message"],
                    "severity": pattern_def["severity"],
                    "languages": ["javascript"],
                    "metadata": {
                        "category": "security",
                        "cwe": pattern_def["cwe"],
                        "confidence": "HIGH",
                        "matched_example": matched_text[:100],
                    },
                }
            )

    if not signatures:
        logger.info(f"No security patterns found in {file_name}")
        signatures.append(
            {
                "rule_id": f"custom-no-patterns-{file_name.replace('.', '-')}",
                "pattern": "// No suspicious patterns detected",
                "message": f"No common security patterns found in {file_name}. File appears clean or uses uncommon patterns.",
                "severity": "INFO",
                "languages": ["javascript"],
                "metadata": {"category": "informational", "cwe": "CWE-710", "confidence": "LOW"},
            }
        )

    return signatures


batch_jobs: Dict[str, Dict[str, Any]] = {}


class BatchAnalyzeRequest(BaseModel):
    """Request model for batch analysis."""

    extensions: list[str]
    parallel: bool = True
    max_workers: int = 4


class BatchStatusResponse(BaseModel):
    """Response model for batch status."""

    batch_id: str
    status: str
    total_extensions: int
    completed: int
    failed: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None


@app.post("/api/batch/analyze")
async def batch_analyze(request: BatchAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Trigger batch analysis of multiple extensions.

    Args:
        request: BatchAnalyzeRequest containing list of extensions and options
        background_tasks: FastAPI background tasks

    Returns:
        Dict with batch_id and initial status
    """
    from threatxtension.core.batch_processor import BatchProcessor

    if not request.extensions:
        raise HTTPException(status_code=400, detail="Extension list cannot be empty")

    if len(request.extensions) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 extensions allowed per batch")

    processor = BatchProcessor(output_dir="./batch_results")

    import uuid

    batch_id = f"batch_{uuid.uuid4().hex[:8]}"

    batch_jobs[batch_id] = {
        "batch_id": batch_id,
        "status": "pending",
        "total_extensions": len(request.extensions),
        "completed": 0,
        "failed": 0,
        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
    }

    async def run_batch():
        try:
            batch_jobs[batch_id]["status"] = "running"
            result = processor.process_batch(
                extension_list=request.extensions,
                batch_id=batch_id,
                parallel=request.parallel,
                max_workers=request.max_workers,
            )
            batch_jobs[batch_id].update(
                {
                    "status": result.get("status", "completed"),
                    "completed": result.get("completed", 0),
                    "failed": result.get("failed", 0),
                    "end_time": result.get("end_time"),
                    "results": result.get("results", []),
                    "report_path": result.get("report_path"),
                }
            )
        except Exception as e:
            logger.error(f"Batch processing failed: {e}", exc_info=True)
            batch_jobs[batch_id].update(
                {
                    "status": "failed",
                    "error": str(e),
                    "end_time": datetime.utcnow().isoformat(),
                }
            )

    background_tasks.add_task(run_batch)

    return {
        "batch_id": batch_id,
        "status": "pending",
        "message": f"Batch analysis started for {len(request.extensions)} extensions",
    }


@app.get("/api/batch/status/{batch_id}")
async def get_batch_status(batch_id: str):
    """
    Get the status of a batch analysis job.

    Args:
        batch_id: Batch identifier

    Returns:
        BatchStatusResponse with current batch status
    """
    if batch_id not in batch_jobs:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found")

    job = batch_jobs[batch_id]

    return BatchStatusResponse(
        batch_id=job["batch_id"],
        status=job["status"],
        total_extensions=job["total_extensions"],
        completed=job.get("completed", 0),
        failed=job.get("failed", 0),
        start_time=job.get("start_time"),
        end_time=job.get("end_time"),
    )


@app.get("/api/batch/results/{batch_id}")
async def get_batch_results(batch_id: str):
    """
    Get the full results of a completed batch analysis.

    Args:
        batch_id: Batch identifier

    Returns:
        Dict containing complete batch results
    """
    if batch_id not in batch_jobs:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found")

    job = batch_jobs[batch_id]

    if job["status"] not in ["completed", "failed"]:
        raise HTTPException(
            status_code=400,
            detail=f"Batch is still {job['status']}. Results not yet available.",
        )

    from threatxtension.core.batch_processor import BatchProcessor

    processor = BatchProcessor(output_dir="./batch_results")
    file_results = processor.get_batch_results(batch_id)

    if file_results:
        return file_results

    return {
        "batch_id": job["batch_id"],
        "status": job["status"],
        "total_extensions": job["total_extensions"],
        "completed": job.get("completed", 0),
        "failed": job.get("failed", 0),
        "start_time": job.get("start_time"),
        "end_time": job.get("end_time"),
        "results": job.get("results", []),
        "error": job.get("error"),
    }


@app.get("/api/batch/list")
async def list_batch_jobs():
    """
    List all batch jobs.

    Returns:
        Dict containing list of all batch jobs with their status
    """
    jobs_list = [
        {
            "batch_id": job["batch_id"],
            "status": job["status"],
            "total_extensions": job["total_extensions"],
            "completed": job.get("completed", 0),
            "failed": job.get("failed", 0),
            "start_time": job.get("start_time"),
            "end_time": job.get("end_time"),
        }
        for job in batch_jobs.values()
    ]

    return {"batches": jobs_list, "total": len(jobs_list)}


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy", "service": "threatxtension", "version": "1.0.0"}


if STATIC_DIR.exists() and (STATIC_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")


# Catch-all route for SPA - must be defined last
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """
    Serve React SPA for all non-API routes.
    This enables client-side routing in the React app.
    """
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)

    return {
        "name": "ThreatXtension API",
        "version": "1.0.0",
        "docs": "/docs",
        "note": "Frontend not built. Run 'npm run build' in frontend/ directory.",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8007)

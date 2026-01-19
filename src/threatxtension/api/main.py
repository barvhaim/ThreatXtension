"""
FastAPI Backend for ThreatXtension

Provides REST API endpoints for the frontend to trigger extension analysis
and retrieve results.
"""

import os
import json

# import asyncio  # Unused import
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import shutil

from threatxtension.core.report_generator import ReportGenerator

from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowState, WorkflowStatus
from threatxtension.api.database import db


# Pydantic models for request/response
class ScanRequest(BaseModel):
    """Request model for triggering a scan."""

    url: str


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


# Initialize FastAPI app
app = FastAPI(
    title="ThreatXtension API",
    description="REST API for Chrome extension security analysis",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",  # Alternative dev port
        "http://localhost:8007",  # Same-origin in container
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory for React frontend (in container)
STATIC_DIR = Path(__file__).parent.parent.parent.parent / "static"

# Storage for scan results (in-memory cache + database persistence)
scan_results: Dict[str, Dict[str, Any]] = {}
scan_status: Dict[str, str] = {}


# Load existing results from database on startup
def load_existing_results():
    """Load existing scan results from database into memory cache."""
    history = db.get_scan_history(limit=100)
    for item in history:
        ext_id = item.get("extension_id")
        if ext_id:
            scan_status[ext_id] = item.get("status", "completed")


load_existing_results()

# Directory for storing analysis results
RESULTS_DIR = Path("extensions_storage")
RESULTS_DIR.mkdir(exist_ok=True)


def extract_extension_id(url: str) -> Optional[str]:
    """Extract extension ID from Chrome Web Store URL."""
    import re

    match = re.search(r"/detail/(?:[^/]+/)?([a-z]{32})", url)
    return match.group(1) if match else None


async def run_analysis_workflow(url: str, extension_id: str):
    """Run the analysis workflow in the background."""
    try:
        # Update status
        scan_status[extension_id] = "running"

        # Build and run workflow
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
            "status": WorkflowStatus.PENDING,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "error": None,
        }

        # Run workflow
        final_state = await graph.ainvoke(initial_state)

        # Store results
        if (
            final_state["status"] == WorkflowStatus.COMPLETED
            or final_state["status"] == "completed"
        ):
            analysis_results = final_state.get("analysis_results", {}) or {}

            # Extract extension name from metadata or manifest
            metadata = final_state.get("extension_metadata") or {}
            manifest = final_state.get("manifest_data") or {}
            extension_name = (
                metadata.get("title")
                or metadata.get("name")
                or manifest.get("name")
                or extension_id
            )

            # Ensure all values are not None
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
                "manifest": manifest,
                "permissions_analysis": analysis_results.get("permissions_analysis") or {},
                "sast_results": analysis_results.get("javascript_analysis") or {},
                "webstore_analysis": analysis_results.get("webstore_analysis") or {},
                "virustotal_analysis": analysis_results.get("virustotal_analysis") or {},
                "entropy_analysis": analysis_results.get("entropy_analysis") or {},
                "summary": final_state.get("executive_summary") or {},
                "extracted_path": final_state.get("extension_dir"),
                "extracted_files": extracted_files,
                "overall_security_score": calculate_security_score(
                    final_state
                ),  # This helper also needs update or a wrapper
                "total_findings": count_total_findings(
                    final_state
                ),  # This helper also needs update or a wrapper
                "risk_distribution": calculate_risk_distribution(
                    final_state
                ),  # This helper also needs update or a wrapper
                "overall_risk": determine_overall_risk(
                    final_state
                ),  # This helper also needs update or a wrapper
                "total_risk_score": calculate_total_risk_score(
                    final_state
                ),  # This helper also needs update or a wrapper
            }
            scan_status[extension_id] = "completed"

            # Save to database
            db.save_scan_result(scan_results[extension_id])

            # Save to file (backup)
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
            # Store relative path from extracted_path
            rel_path = os.path.relpath(file_path, extracted_path)
            files.append(rel_path)

    return files


def calculate_security_score(state: WorkflowState) -> int:
    """
    Calculate overall security RISK score using weighted multi-factor analysis.

    Scoring Components (0-100 scale, where 100 = HIGHEST RISK):
    - SAST Findings (40%): Critical code vulnerabilities
    - Permissions Risk (30%): Unreasonable/excessive permissions
    - Webstore Trust (20%): User ratings, install count, developer reputation
    - Manifest Quality (10%): Proper metadata, CSP, update URL

    Returns:
        int: Risk score from 0 (safest) to 100 (highest risk)
    """
    analysis_results = state.get("analysis_results", {}) or {}
    manifest = state.get("manifest_data", {}) or {}

    # Component 1: SAST Analysis (40 points max risk)
    sast_score = 0  # Start at 0 risk
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            for finding in findings_list:
                severity = finding.get("extra", {}).get("severity", "INFO").upper()
                if severity in ("CRITICAL", "HIGH"):
                    sast_score += 8  # Add risk points
                elif severity in ("ERROR", "MEDIUM"):
                    sast_score += 4
                elif severity == "WARNING":
                    sast_score += 1
    sast_score = min(40, sast_score)  # Cap at 40

    # Component 2: Permissions Analysis (30 points max risk)
    permissions_score = 0  # Start at 0 risk
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
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
                permissions_score += 5  # Add risk points
            elif risk == "medium":
                permissions_score += 2
            else:
                permissions_score += 1

    permissions_score = min(30, permissions_score)  # Cap at 30

    # Component 3: Webstore Trust Score (20 points max risk)
    webstore_score = 0  # Start at 0 risk
    _ = analysis_results.get("webstore_analysis", {})  # webstore_analysis - for future use
    metadata = state.get("extension_metadata", {}) or {}

    # Check user ratings (low rating = higher risk)
    rating = metadata.get("rating")
    if rating:
        try:
            rating_val = float(rating)
            if rating_val >= 4.5:
                webstore_score += 0  # Excellent - no risk
            elif rating_val >= 4.0:
                webstore_score += 2  # Good - slight risk
            elif rating_val >= 3.0:
                webstore_score += 5  # Average - moderate risk
            else:
                webstore_score += 10  # Poor - high risk
        except (ValueError, TypeError):
            webstore_score += 3  # No valid rating - some risk
    else:
        webstore_score += 3  # No rating data

    # Check install count (low adoption = higher risk)
    users = metadata.get("users", "0")
    try:
        user_count = int(users.replace(",", "").replace("+", ""))
        if user_count >= 1000000:
            webstore_score += 0  # Very popular - trusted
        elif user_count >= 100000:
            webstore_score += 2  # Popular - low risk
        elif user_count >= 10000:
            webstore_score += 5  # Moderate - some risk
        else:
            webstore_score += 8  # Low adoption - higher risk
    except (ValueError, TypeError):
        webstore_score += 5  # Unknown user count

    webstore_score = min(20, webstore_score)  # Cap at 20

    # Component 4: Manifest Quality (10 points max risk)
    manifest_score = 0  # Start at 0 risk

    # Check for proper metadata (missing = risk)
    if not manifest.get("name") or manifest.get("name", "").startswith("__MSG_"):
        manifest_score += 3  # Missing/placeholder name = risk
    if not manifest.get("description") or manifest.get("description", "").startswith("__MSG_"):
        manifest_score += 2  # Missing/placeholder description = risk

    # Check for Content Security Policy (missing = risk)
    if not manifest.get("content_security_policy"):
        manifest_score += 2

    # Check for update URL (missing = risk)
    if not manifest.get("update_url"):
        manifest_score += 1

    manifest_score = min(10, manifest_score)  # Cap at 10

    # Calculate final weighted score
    final_score = sast_score + permissions_score + webstore_score + manifest_score

    return max(0, min(100, final_score))


def count_total_findings(state: WorkflowState) -> int:
    """Count total security findings including unreasonable permissions."""
    analysis_results = state.get("analysis_results", {}) or {}

    # Count SAST findings
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    total = 0
    if javascript_analysis:
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            if findings_list is not None:
                total += len(findings_list)

    # Count unreasonable permissions as findings
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
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

    # Count SAST findings
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

    # Count unreasonable permissions as findings
    permissions_analysis = analysis_results.get("permissions_analysis", {}) or {}
    permissions_details = (
        permissions_analysis.get("permissions_details")
        if isinstance(permissions_analysis, dict)
        else None
    )
    # Ensure permissions_details is a dict, not None
    if not isinstance(permissions_details, dict):
        permissions_details = {}

    for _, perm_analysis in permissions_details.items():
        is_reasonable = perm_analysis.get("is_reasonable", True)
        risk = perm_analysis.get("risk_level", "").lower()

        if not is_reasonable:
            # Classify unreasonable permissions by explicit risk_level or default to medium
            if risk == "high":
                distribution["high"] += 1
            elif risk == "low":
                distribution["low"] += 1
            else:
                # Default unreasonable permissions to medium risk
                distribution["medium"] += 1

    return distribution


def determine_overall_risk(state: WorkflowState) -> str:
    """Determine overall risk level."""
    score = calculate_security_score(state)

    if score < 30:
        return "high"
    if score < 70:
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
    # map severity to score if risk_score not present
    severity_scores = {"CRITICAL": 10, "HIGH": 8, "ERROR": 5, "MEDIUM": 5, "WARNING": 1, "INFO": 0}

    for finding in js_analysis:
        severity = finding.get("extra", {}).get("severity", "INFO")
        total_score += severity_scores.get(severity, 0)

    return total_score


# API Endpoints


@app.get("/")
async def root():
    """Root endpoint - serves frontend or API info."""
    # Serve frontend if available
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)
    # Otherwise return API info (development mode)
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
    extension_id = extract_extension_id(url)

    if not extension_id:
        raise HTTPException(status_code=400, detail="Invalid Chrome Web Store URL")

    # Check if already scanning
    if extension_id in scan_status and scan_status[extension_id] == "running":
        return {
            "message": "Scan already in progress",
            "extension_id": extension_id,
            "status": "running",
        }

    # Start background analysis
    background_tasks.add_task(run_analysis_workflow, url, extension_id)

    return {
        "message": "Scan triggered successfully",
        "extension_id": extension_id,
        "status": "running",
    }


@app.post("/api/scan/upload")
async def upload_and_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Upload a CRX/ZIP file and trigger analysis.

    Args:
        file: Uploaded CRX or ZIP file
        background_tasks: FastAPI background tasks

    Returns:
        Scan trigger confirmation with extension ID
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    filename_lower = file.filename.lower()
    if not (filename_lower.endswith('.crx') or filename_lower.endswith('.zip')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .crx and .zip files are supported"
        )

    # Validate file size (max 100MB)
    max_size = 100 * 1024 * 1024  # 100MB
    file_content = await file.read()
    if len(file_content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {max_size / (1024*1024):.0f}MB"
        )

    # Generate unique ID for uploaded file
    import uuid
    extension_id = str(uuid.uuid4())

    # Save uploaded file to extensions_storage
    file_path = RESULTS_DIR / f"{extension_id}_{file.filename}"

    try:
        with open(file_path, "wb") as buffer:
            buffer.write(file_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    # Start background analysis with local file path
    background_tasks.add_task(run_analysis_workflow, str(file_path), extension_id)

    return {
        "message": "File uploaded and scan triggered successfully",
        "extension_id": extension_id,
        "filename": file.filename,
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
    # Try memory first
    if extension_id in scan_results:
        return scan_results[extension_id]

    # Try loading from database
    results = db.get_scan_result(extension_id)
    if results:
        # Ensure consistent field naming for frontend
        formatted_results = {
            "extension_id": results.get("extension_id"),
            "extension_name": results.get("extension_name"),
            "url": results.get("url"),
            "timestamp": results.get("timestamp"),
            "status": results.get("status"),
            "metadata": results.get("metadata", {}),
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
        scan_results[extension_id] = formatted_results  # Cache in memory
        return formatted_results

    # Try loading from file (fallback)
    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    if result_file.exists():
        with open(result_file, "r", encoding="utf-8") as f:
            results = json.load(f)
            scan_results[extension_id] = results  # Cache in memory
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
    # Get scan results
    results = scan_results.get(extension_id)

    # Try database if not in memory
    if not results:
        results = db.get_scan_result(extension_id)
        if results:
            scan_results[extension_id] = results

    # Try filesystem if not in database
    if not results:
        results_file = RESULTS_DIR / f"{extension_id}_results.json"
        if results_file.exists():
            with open(results_file, "r", encoding="utf-8") as f:
                results = json.load(f)
                scan_results[extension_id] = results

    if not results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    # Generate PDF report
    try:
        report_generator = ReportGenerator()
        if not report_generator.enabled:
            raise HTTPException(
                status_code=503,
                detail="PDF generation is disabled. Install weasyprint to enable."
            )

        pdf_bytes = report_generator.generate_pdf(results)

        # Get extension name for filename
        extension_name = results.get("extension_name", results.get("metadata", {}).get("title", extension_id))
        safe_name = "".join(c for c in extension_name if c.isalnum() or c in " -_")[:50]
        filename = f"ThreatXtension_Report_{safe_name}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
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

    # Construct full file path
    full_path = os.path.join(extracted_path, file_path)

    # Security check: ensure path is within extracted directory
    if not os.path.abspath(full_path).startswith(os.path.abspath(extracted_path)):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        return FileContentResponse(content=content, file_path=file_path)
    except UnicodeDecodeError as exc:
        # Binary file
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
        # Remove from memory cache
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


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy", "service": "threatxtension", "version": "1.0.0"}


# Mount static files for React frontend assets (if static directory exists)
if STATIC_DIR.exists() and (STATIC_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")


# Catch-all route for SPA - must be defined last
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """
    Serve React SPA for all non-API routes.
    This enables client-side routing in the React app.
    """
    # Don't intercept API routes
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    # Serve index.html for all other routes (SPA routing)
    index_file = STATIC_DIR / "index.html"
    if STATIC_DIR.exists() and index_file.exists():
        return FileResponse(index_file)

    # If no static files, return API info (development mode)
    return {
        "name": "ThreatXtension API",
        "version": "1.0.0",
        "docs": "/docs",
        "note": "Frontend not built. Run 'npm run build' in frontend/ directory.",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8007)

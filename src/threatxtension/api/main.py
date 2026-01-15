"""
FastAPI Backend for ThreatXtension

Provides REST API endpoints for the frontend to trigger extension analysis
and retrieve results.
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowState, WorkflowStatus


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
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage for scan results (in-memory for now, could be Redis/DB later)
scan_results: Dict[str, Dict[str, Any]] = {}
scan_status: Dict[str, str] = {}

# Directory for storing analysis results
RESULTS_DIR = Path("extensions_storage")
RESULTS_DIR.mkdir(exist_ok=True)


def extract_extension_id(url: str) -> Optional[str]:
    """Extract extension ID from Chrome Web Store URL."""
    import re
    match = re.search(r'/detail/[^/]+/([a-z]{32})', url)
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
            "status": WorkflowStatus.PENDING,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "error": None,
        }
        
        # Run workflow
        final_state = await graph.ainvoke(initial_state)
        
        # Store results
        if final_state["status"] == WorkflowStatus.COMPLETED or final_state["status"] == "completed":
            analysis_results = final_state.get("analysis_results", {}) or {}
            
            scan_results[extension_id] = {
                "extension_id": extension_id,
                "url": url,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "metadata": final_state.get("extension_metadata", {}),
                "manifest": final_state.get("manifest_data", {}),
                "permissions_analysis": analysis_results.get("permissions_analysis", {}),
                "sast_results": analysis_results.get("javascript_analysis", {}),
                "webstore_analysis": analysis_results.get("webstore_analysis", {}),
                "summary": final_state.get("executive_summary", {}),
                "extracted_path": final_state.get("extension_dir"),
                "extracted_files": get_extracted_files(final_state.get("extension_dir")),
                "overall_security_score": calculate_security_score(final_state), # This helper also needs update or a wrapper
                "total_findings": count_total_findings(final_state), # This helper also needs update or a wrapper
                "risk_distribution": calculate_risk_distribution(final_state), # This helper also needs update or a wrapper
                "overall_risk": determine_overall_risk(final_state), # This helper also needs update or a wrapper
                "total_risk_score": calculate_total_risk_score(final_state), # This helper also needs update or a wrapper
            }
            scan_status[extension_id] = "completed"
            
            # Save to file
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
    """Calculate overall security score from analysis results."""
    # Start with perfect score
    score = 100
    
    analysis_results = state.get("analysis_results", {}) or {}
    
    # Deduct for SAST findings
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    js_analysis = []
    if javascript_analysis and isinstance(javascript_analysis, dict):
        sast_findings = javascript_analysis.get("sast_findings", {})
        for findings_list in sast_findings.values():
            js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
        # Fallback if it is a list
        js_analysis = javascript_analysis

    for finding in js_analysis:
        risk_level = finding.get("extra", {}).get("severity", "INFO") # Semgrep returns severity in extra.severity or just top level? 
        # Checking sast.py: severity = finding.get("extra", {}).get("severity", "INFO")
        
        # Map semgrep severity to score deduction
        if risk_level == "CRITICAL" or risk_level == "HIGH":
            score -= 20
        elif risk_level == "ERROR" or risk_level == "MEDIUM":
            score -= 10
        elif risk_level == "WARNING":
            score -= 2
            
    # Deduct for risky permissions
    permissions_analysis = analysis_results.get("permissions_analysis", {})
    permissions_details = permissions_analysis.get("permissions_details", {}) if isinstance(permissions_analysis, dict) else {}
    
    for _, perm_analysis in permissions_details.items():
        # Permission analysis format: {"is_reasonable": bool, "risk_level": "low/medium/high", ...}
        # Note: permissions.py returns {permission: {JSON from LLM}}
        # We need to verify the structure or assume LLM returns risk_level
        risk = perm_analysis.get("risk_level", "low").lower()
        if risk == "high":
            score -= 15
        elif risk == "medium":
            score -= 5
    
    return max(0, min(100, score))


def count_total_findings(state: WorkflowState) -> int:
    """Count total security findings."""
    analysis_results = state.get("analysis_results", {}) or {}
    javascript_analysis = analysis_results.get("javascript_analysis", {})
    
    total = 0
    if javascript_analysis:
         sast_findings = javascript_analysis.get("sast_findings", {})
         for findings_list in sast_findings.values():
             total += len(findings_list)
             
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
            js_analysis.extend(findings_list)
    elif isinstance(javascript_analysis, list):
         js_analysis = javascript_analysis
    
    for finding in js_analysis:
        risk_level = finding.get("extra", {}).get("severity", "INFO").lower() # Semgrep format
        if risk_level == "critical" or risk_level == "high":
            distribution["high"] += 1
        elif risk_level == "error" or risk_level == "medium":
            distribution["medium"] += 1
        else:
            distribution["low"] += 1
    
    return distribution


def determine_overall_risk(state: WorkflowState) -> str:
    """Determine overall risk level."""
    score = calculate_security_score(state)
    
    if score < 30:
        return "high"
    elif score < 70:
        return "medium"
    else:
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
    """Root endpoint."""
    return {
        "name": "ThreatXtension API",
        "version": "1.0.0",
        "status": "running"
    }


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
            "status": "running"
        }
    
    # Start background analysis
    background_tasks.add_task(run_analysis_workflow, url, extension_id)
    
    return {
        "message": "Scan triggered successfully",
        "extension_id": extension_id,
        "status": "running"
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
        error=result.get("error")
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
    
    # Try loading from file
    result_file = RESULTS_DIR / f"{extension_id}_results.json"
    if result_file.exists():
        with open(result_file, "r", encoding="utf-8") as f:
            results = json.load(f)
            scan_results[extension_id] = results  # Cache in memory
            return results
    
    raise HTTPException(status_code=404, detail="Scan results not found")


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
    except UnicodeDecodeError:
        # Binary file
        raise HTTPException(status_code=400, detail="Cannot read binary file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)

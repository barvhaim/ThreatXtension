"""
Workflow State Management

This module defines the state structure and status enum for the extension analysis workflow.
"""

from enum import Enum
from typing import Optional, Dict
from typing_extensions import TypedDict


class WorkflowStatus(str, Enum):
    """Enum representing possible workflow statuses."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowState(TypedDict):
    """
    Represents the state of a workflow in the system.

    Attributes:
        workflow_id (str): Unique identifier for the workflow.
        chrome_extension_path (str): File path to the Chrome extension being analyzed.
        extension_dir (Optional[str]): Directory where the extension is extracted,
            if available.
        extension_metadata (Optional[Dict]): Metadata extracted from the extension,
            if available.
        manifest_data (Optional[Dict]): Parsed manifest.json data of the extension.
        analysis_results (Optional[Dict]): Results from all analyzers (permissions,
            webstore, SAST).
        executive_summary (Optional[Dict]): Executive summary with overall risk assessment,
            key findings, and recommendations.
        status (WorkflowStatus): Current status of the workflow.
        start_time (Optional[str]): ISO 8601 formatted start time of the workflow,
            if available.
        end_time (Optional[str]): ISO 8601 formatted end time of the workflow, if available.
        error (Optional[str]): Error message if the workflow has failed, otherwise None.
    """

    workflow_id: str
    chrome_extension_path: str
    extension_dir: Optional[str]
    extension_metadata: Optional[Dict]
    manifest_data: Optional[Dict]
    analysis_results: Optional[Dict]
    executive_summary: Optional[Dict]
    status: WorkflowStatus
    start_time: Optional[str]
    end_time: Optional[str]
    error: Optional[str]

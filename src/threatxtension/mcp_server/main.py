"""Main MCP server for ThreatXtension Chrome extension analysis."""

import uuid
import json
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowStatus


mcp = FastMCP("ThreatXtension")


@mcp.tool()
def analyze_chrome_extension(chrome_extension_url: str) -> str:
    """
    Analyzes a Chrome extension from the Chrome Web Store
    and returns a comprehensive security assessment.

    Args:
        chrome_extension_url (str): The Chrome Web Store URL of the extension to analyze.

    Returns:
        str: JSON string containing complete analysis results including metadata, executive summary,
             permissions analysis, SAST findings, and webstore reputation analysis.
    """
    # Build the workflow graph
    graph = build_graph()

    # Create initial workflow state
    initial_state = {
        "workflow_id": str(uuid.uuid4()),
        "chrome_extension_path": chrome_extension_url,
        "extension_dir": None,
        "extension_metadata": None,
        "manifest_data": None,
        "analysis_results": None,
        "executive_summary": None,
        "status": WorkflowStatus.PENDING.value,
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "error": None,
    }

    # Execute workflow
    result = graph.invoke(initial_state)

    # Check for errors
    if result.get("status") == WorkflowStatus.FAILED.value:
        return json.dumps(
            {
                "status": "failed",
                "error": result.get("error", "Unknown error occurred"),
            },
            indent=2,
        )

    # Return executive summary and extension metadata only
    response = {
        "status": "success",
        "executive_summary": result.get("executive_summary", {}),
        "extension_metadata": result.get("extension_metadata", {}),
    }

    return json.dumps(response, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")

"""
Gradio UI for ThreatXtension Chrome Extension Analysis

This module provides a web-based interface for analyzing Chrome extensions
using the LangGraph workflow.

Usage:
    uv run python src/threatxtension/ui/app.py
"""

import uuid
import json
import logging
import os
import tempfile
import shutil
from datetime import datetime
import gradio as gr
from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowStatus

logger = logging.getLogger(__name__)


def configure_logging():
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def format_summary(summary_data):
    """Format the executive summary for display.

    Args:
        summary_data: Dictionary containing summary, risk level, findings, and recommendations.

    Returns:
        Formatted markdown string.
    """
    if not summary_data:
        return "## Executive Summary\n\nNo summary available. Please try analyzing again."
    
    # Handle case where summary_data might be a string or invalid format
    if not isinstance(summary_data, dict):
        return f"## Executive Summary\n\n{str(summary_data)}"

    risk_level = summary_data.get("overall_risk_level", "unknown")
    if isinstance(risk_level, str):
        risk_level = risk_level.upper()
    else:
        risk_level = "UNKNOWN"
    
    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(risk_level, "⚪")

    formatted = f"## {risk_emoji} Risk Level: {risk_level}\n\n"
    
    summary_text = summary_data.get("summary", summary_data.get("summary_text", "N/A"))
    if summary_text:
        formatted += f"### Summary\n{summary_text}\n\n"

    key_findings = summary_data.get("key_findings", summary_data.get("findings", []))
    if key_findings and isinstance(key_findings, list) and len(key_findings) > 0:
        formatted += "### 🔍 Key Findings\n"
        for finding in key_findings:
            if finding:  # Skip empty findings
                formatted += f"- {finding}\n"
        formatted += "\n"

    recommendations = summary_data.get("recommendations", summary_data.get("recommendation", []))
    if recommendations:
        if isinstance(recommendations, list):
            if len(recommendations) > 0:
                formatted += "### 💡 Recommendations\n"
                for rec in recommendations:
                    if rec:  # Skip empty recommendations
                        formatted += f"- {rec}\n"
        else:
            # Handle case where recommendations is a string
            formatted += "### 💡 Recommendations\n"
            formatted += f"- {recommendations}\n"

    return formatted


def format_metadata(metadata_data, manifest_data=None):
    """Format the extension metadata as a markdown table.

    Args:
        metadata_data: Dictionary containing extension metadata from Chrome Web Store.
        manifest_data: Dictionary containing manifest.json data (used as fallback).

    Returns:
        Formatted markdown table string.
    """
    formatted = "## Extension Information\n\n"
    
    # Use manifest data as fallback if metadata is not available (for local files)
    data_source = metadata_data if metadata_data else (manifest_data or {})
    
    if not data_source:
        return "No metadata available. For Chrome Web Store extensions, metadata includes ratings and user counts."
    
    # Show note if using manifest data (local file)
    if not metadata_data and manifest_data:
        formatted += "> ℹ️ **Note:** This extension was analyzed from an uploaded file. "
        formatted += "Chrome Web Store metadata (ratings, user count, etc.) is only available for URLs.\n\n"
    
    formatted += "| Property | Value |\n"
    formatted += "|----------|-------|\n"

    # Define field mappings with nice labels (Chrome Web Store metadata)
    metadata_field_mappings = {
        "title": "Title",
        "version": "Version",
        "user_count": "Users",
        "rating": "Rating",
        "ratings_count": "Ratings Count",
        "last_updated": "Last Updated",
        "size": "Size",
        "category": "Category",
        "developer_name": "Developer",
        "developer_email": "Email",
        "developer_website": "Website",
        "follows_best_practices": "Best Practices",
        "is_featured": "Featured",
    }
    
    # Manifest field mappings (for local files)
    # First, show basic fields
    basic_manifest_fields = {
        "name": "Name",
        "version": "Version",
        "description": "Description",
        "manifest_version": "Manifest Version",
        "author": "Author",
        "homepage_url": "Homepage",
    }
    
    # Additional manifest fields that provide useful info
    additional_manifest_fields = {
        "update_url": "Update URL",
        "permissions": "Permissions Count",
        "host_permissions": "Host Permissions Count",
        "content_scripts": "Content Scripts Count",
        "optional_permissions": "Optional Permissions Count",
    }

    # Use appropriate field mappings based on data source
    if metadata_data:
        field_mappings = metadata_field_mappings
    else:
        field_mappings = basic_manifest_fields

    # Display basic fields first
    for key, label in field_mappings.items():
        if key in data_source:
            value = data_source[key]

            # Format specific fields
            if key == "user_count" and isinstance(value, (int, float)):
                value = f"{int(value):,}"
            elif key == "ratings_count" and isinstance(value, (int, float)):
                value = f"{int(value):,}"
            elif key in ["follows_best_practices", "is_featured"]:
                value = "Yes" if value else "No"
            elif value is None:
                continue

            formatted += f"| {label} | {value} |\n"
    
    # For local files, also show additional manifest information
    if not metadata_data and manifest_data:
        formatted += "\n### Additional Information from Manifest\n\n"
        formatted += "| Property | Value |\n"
        formatted += "|----------|-------|\n"
        
        # Show permissions count
        permissions = manifest_data.get("permissions", [])
        if permissions:
            formatted += f"| Permissions Count | {len(permissions)} |\n"
        
        # Show host permissions count
        host_permissions = manifest_data.get("host_permissions", [])
        if host_permissions:
            formatted += f"| Host Permissions Count | {len(host_permissions)} |\n"
        
        # Show content scripts count
        content_scripts = manifest_data.get("content_scripts", [])
        if content_scripts:
            formatted += f"| Content Scripts Count | {len(content_scripts)} |\n"
        
        # Show optional permissions count
        optional_permissions = manifest_data.get("optional_permissions", [])
        if optional_permissions:
            formatted += f"| Optional Permissions Count | {len(optional_permissions)} |\n"
        
        # Show update URL if available
        update_url = manifest_data.get("update_url")
        if update_url:
            formatted += f"| Update URL | {update_url} |\n"
        
        # Show if there's a background script/service worker
        background = manifest_data.get("background")
        if background:
            formatted += "| Background Script | Yes |\n"
        
        # Show if there's an action/browser_action
        action = manifest_data.get("action")
        if action:
            formatted += "| Browser Action | Yes |\n"
        
        # Show web accessible resources count
        web_accessible_resources = manifest_data.get("web_accessible_resources", [])
        if web_accessible_resources:
            formatted += f"| Web Accessible Resources | {len(web_accessible_resources)} |\n"
        
        # Show note about Chrome Web Store only fields
        formatted += "\n"
        formatted += "> ⚠️ **Note:** The following information is only available from Chrome Web Store: "
        formatted += "Users, Rating, Last Updated, Size, Category, Best Practices, Featured, Developer Email\n"

    return formatted


def analyze_extension(extension_url: str, uploaded_file, progress=gr.Progress()):
    """Analyze a Chrome extension using the workflow.

    Args:
        extension_url: Chrome Web Store URL of the extension (optional if file is provided).
        uploaded_file: Uploaded CRX or ZIP file (optional if URL is provided).
        progress: Gradio progress tracker.

    Returns:
        Tuple of analysis results for display.
    """
    try:
        chrome_extension_path = None
        temp_file_path = None

        # Determine input source: file upload takes precedence
        if uploaded_file is not None:
            # Handle file upload
            # Gradio file upload returns a FileData object with .name attribute
            file_path = uploaded_file.name if hasattr(uploaded_file, 'name') else str(uploaded_file)
            
            if not file_path or not os.path.exists(file_path):
                return ["Uploaded file not found or invalid", None, None]
            
            # Validate file extension
            if not (file_path.lower().endswith(".crx") or 
                    file_path.lower().endswith(".zip")):
                return ["Please upload a .crx or .zip file", None, None]
            
            # Copy uploaded file to a temporary location
            # Gradio may delete the temp file, so we need our own copy
            temp_dir = tempfile.mkdtemp(prefix="threatxtension_upload_")
            temp_file_path = os.path.join(temp_dir, os.path.basename(file_path))
            shutil.copy2(file_path, temp_file_path)
            chrome_extension_path = temp_file_path
            logger.info("Using uploaded file: %s", chrome_extension_path)
            
        elif extension_url and extension_url.strip():
            # Use URL
            chrome_extension_path = extension_url.strip().split("?")[0]
            logger.info("Using extension URL: %s", chrome_extension_path)
        else:
            return ["Please provide either a Chrome Web Store URL or upload a .crx/.zip file", None, None]

        progress(0.1, desc="Initializing workflow...")

        # Build workflow graph
        graph = build_graph()

        # Create initial state
        initial_state = {
            "workflow_id": str(uuid.uuid4()),
            "chrome_extension_path": chrome_extension_path,
            "extension_dir": None,
            "extension_metadata": None,
            "analysis_results": None,
            "status": WorkflowStatus.PENDING.value,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "error": None,
        }

        progress(0.5, desc="Executing workflow...")

        # Execute workflow
        result = graph.invoke(initial_state)

        progress(1.0, desc="Complete!")

        # Cleanup temporary file if we created one
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                temp_dir = os.path.dirname(temp_file_path)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as cleanup_exc:
                logger.warning("Failed to cleanup temp file: %s", cleanup_exc)

        if result.get("error"):
            return [f"Analysis failed: {result.get('error')}", None, None]

        # Get summary and handle None case
        summary_data = result.get("executive_summary")
        summary_text = format_summary(summary_data)
        
        # Get metadata and manifest for display
        metadata_data = result.get("extension_metadata")
        manifest_data = result.get("manifest_data")
        metadata_text = format_metadata(metadata_data, manifest_data)
        
        return [
            summary_text,
            metadata_text,
            json.dumps(result, indent=2),
        ]

    except Exception as e:
        logger.exception("Error analyzing extension")
        return [
            f"An error occurred during analysis: {str(e)}",
            None,
            None,
        ]


def create_ui() -> gr.Blocks:
    """Create the Gradio UI interface.

    Returns:
        Gradio Blocks interface.
    """
    # Configure theme with IBM Plex Sans font
    theme = gr.themes.Soft(
        font=[
            gr.themes.GoogleFont("IBM Plex Sans"),
            "ui-sans-serif",
            "system-ui",
            "sans-serif",
        ],
        font_mono=[
            gr.themes.GoogleFont("IBM Plex Mono"),
            "ui-monospace",
            "monospace",
        ],
    )

    with gr.Blocks(
        title="️ThreatXtension",
        theme=theme,
        css="""
        /* IBM Plex Sans font family */
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

        body {
            font-family: 'IBM Plex Sans', ui-sans-serif, system-ui, sans-serif;
        }

        code, pre {
            font-family: 'IBM Plex Mono', ui-monospace, monospace;
        }
        """,
    ) as demo:  # pylint: disable=redefined-outer-name

        # Header
        gr.Markdown(
            """# 🛡 ThreatXtension
AI-powered Chrome Extension Analysis Tool
"""
        )
        
        with gr.Tabs() as input_tabs:
            with gr.Tab("📥 URL"):
                with gr.Group():
                    extension_url = gr.Textbox(
                        label="Chrome Web Store URL",
                        placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id",
                        scale=4,
                    )
                    analyze_url_btn = gr.Button("Analyze from URL", variant="primary")
            
            with gr.Tab("📁 Upload File"):
                with gr.Group():
                    uploaded_file = gr.File(
                        label="Upload CRX or ZIP file",
                        file_types=[".crx", ".zip"],
                    )
                    analyze_file_btn = gr.Button("Analyze from File", variant="primary")

        with gr.Tabs():
            with gr.Tab("🧪 Results"):
                with gr.Row():
                    with gr.Column():
                        summary = gr.Markdown(
                            label="Executive Summary",
                            value="Enter a Chrome Web Store URL and click Analyze to view results.",
                        )
                    with gr.Column():
                        metadata = gr.Markdown(
                            label="Extension Metadata",
                        )

            with gr.Tab("📦 Raw Output"):
                raw_output = gr.Textbox(
                    label="Raw Output",
                    lines=30,
                    value="Enter a Chrome Web Store URL and click Analyze to view results.",
                )

            with gr.Tab("❓ About"):
                gr.Markdown(
                    """
                    ## About ThreatXtension
                    ThreatXtension is an AI-powered tool designed to analyze Chrome
                    extensions for potential security risks.
                    By leveraging advanced analysis techniques, it provides users with
                    insights into the safety and reliability of extensions before
                    installation.

                    ### Features
                    - **Extension Analysis**: Analyze Chrome extensions from URLs or uploaded files
                    - **Multiple Input Methods**: Use Chrome Web Store URLs or upload .crx/.zip files directly
                    - **Executive Summary**: Get a concise summary highlighting key
                    findings and risk assessments.
                    - **Metadata Extraction**: View detailed metadata about the extension,
                    including permissions and developer information.

                    ### Usage
                    **Option 1: URL Analysis**
                    1. Go to the "URL" tab
                    2. Enter the Chrome Web Store URL of the extension you wish to analyze
                    3. Click the "Analyze from URL" button
                    
                    **Option 2: File Upload**
                    1. Go to the "Upload File" tab
                    2. Upload a .crx or .zip file of the extension
                    3. Click the "Analyze from File" button
                    
                    4. Review the results in the "Results" tab

                    ### Disclaimer
                    ThreatXtension is a research tool and should not be solely relied
                    upon for making security decisions. Always exercise caution when
                    installing browser extensions.
                    """
                )

        # pylint: disable=no-member
        # Create a wrapper function for URL analysis
        def analyze_from_url(url):
            return analyze_extension(url, None)
        
        # Create a wrapper function for file analysis
        def analyze_from_file(file):
            if file is None:
                return ["Please upload a .crx or .zip file", None, None]
            return analyze_extension("", file)
        
        analyze_url_btn.click(
            fn=analyze_from_url,
            inputs=[extension_url],
            outputs=[summary, metadata, raw_output],
        )
        
        analyze_file_btn.click(
            fn=analyze_from_file,
            inputs=[uploaded_file],
            outputs=[summary, metadata, raw_output],
        )

    return demo


configure_logging()

demo = create_ui()
demo.launch(server_name="0.0.0.0", server_port=7860)

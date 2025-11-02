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
        return "No summary available"

    risk_level = summary_data.get("overall_risk_level", "unknown").upper()
    risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}.get(risk_level, "⚪")

    formatted = f"## {risk_emoji} Risk Level: {risk_level}\n\n"
    formatted += f"### Summary\n{summary_data.get('summary', 'N/A')}\n\n"

    key_findings = summary_data.get("key_findings", [])
    if key_findings:
        formatted += "### 🔍 Key Findings\n"
        for finding in key_findings:
            formatted += f"- {finding}\n"
        formatted += "\n"

    recommendations = summary_data.get("recommendations", [])
    if recommendations:
        formatted += "### 💡 Recommendations\n"
        for rec in recommendations:
            formatted += f"- {rec}\n"

    return formatted


def format_metadata(metadata_data):
    """Format the extension metadata as a markdown table.

    Args:
        metadata_data: Dictionary containing extension metadata.

    Returns:
        Formatted markdown table string.
    """
    if not metadata_data:
        return "No metadata available"

    formatted = "## Extension Information\n\n"
    formatted += "| Property | Value |\n"
    formatted += "|----------|-------|\n"

    # Define field mappings with nice labels
    field_mappings = {
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

    for key, label in field_mappings.items():
        if key in metadata_data:
            value = metadata_data[key]

            # Format specific fields
            if key == "user_count" and isinstance(value, (int, float)):
                value = f"{int(value):,}"
            elif key in ["follows_best_practices", "is_featured"]:
                value = "Yes" if value else "No"

            formatted += f"| {label} | {value} |\n"

    return formatted


def analyze_extension(extension_url: str, progress=gr.Progress()):
    """Analyze a Chrome extension using the workflow.

    Args:
        extension_url: Chrome Web Store URL of the extension.
        progress: Gradio progress tracker.

    Returns:
        Tuple of analysis results for display.
    """
    try:
        # Validate input
        if not extension_url or not extension_url.strip():
            return ["Please enter a valid Chrome Web Store URL", None, None]

        progress(0.1, desc="Initializing workflow...")

        # Build workflow graph
        graph = build_graph()

        # Create initial state
        initial_state = {
            "workflow_id": str(uuid.uuid4()),
            "chrome_extension_path": extension_url.strip().split("?")[0],
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

        if result.get("error"):
            return [f"Analysis failed: {result.get('error')}", None, None]

        return [
            format_summary(result.get("executive_summary")),
            format_metadata(result.get("extension_metadata")),
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
        with gr.Group():
            extension_url = gr.Textbox(
                label="Extension URL",
                placeholder="https://chromewebstore.google.com/detail/extension-name/extension-id",
                scale=4,
            )
            analyze_btn = gr.Button("Analyze", variant="primary")

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
                    - **Extension Analysis**: Input a Chrome Web Store URL to receive a
                    comprehensive analysis of the extension.
                    - **Executive Summary**: Get a concise summary highlighting key
                    findings and risk assessments.
                    - **Metadata Extraction**: View detailed metadata about the extension,
                    including permissions and developer information.

                    ### Usage
                    1. Enter the Chrome Web Store URL of the extension you wish to
                    analyze.
                    2. Click the "Analyze" button to initiate the analysis.
                    3. Review the results in the "Results" tab.

                    ### Disclaimer
                    ThreatXtension is a research tool and should not be solely relied
                    upon for making security decisions. Always exercise caution when
                    installing browser extensions.
                    """
                )

        # pylint: disable=no-member
        analyze_btn.click(
            fn=analyze_extension,
            inputs=[extension_url],
            outputs=[summary, metadata, raw_output],
        )

    return demo


configure_logging()

demo = create_ui()
demo.launch(server_name="0.0.0.0", server_port=7860)

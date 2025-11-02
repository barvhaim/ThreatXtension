#!/usr/bin/env -S uv run
"""
Example script demonstrating how to use the LangGraph workflow for Chrome extension analysis.

Usage:
    uv run examples/workflow.py
"""

import uuid
import logging
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowStatus


logger = logging.getLogger(__name__)
console = Console()


def configure_logging():
    """Configure logging for the workflow."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def print_header():
    """Print workflow header."""
    console.print(
        Panel.fit(
            "[bold cyan]Chrome Extension Analysis Workflow[/bold cyan]",
            border_style="cyan",
        )
    )


def create_initial_state(chrome_extension_path: str) -> dict:
    """Create initial workflow state.

    Args:
        chrome_extension_path: Path of the Chrome extension to use in the workflow.

    Returns:
        Initial workflow state dictionary.
    """
    return {
        "workflow_id": str(uuid.uuid4()),
        "chrome_extension_path": chrome_extension_path,
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


def print_initial_state(state: dict):
    """Print the initial workflow state.

    Args:
        state: Initial workflow state dictionary.
    """
    console.print("\n[bold]Initial State:[/bold]")
    console.print(f"  Workflow ID: [yellow]{state['workflow_id']}[/yellow]")
    console.print(f"  Chrome Extension URL: [blue]{state['chrome_extension_path']}[/blue]")
    console.print(f"  Start Time: [green]{state['start_time']}[/green]\n")


def calculate_duration(start_time: str, end_time: str) -> float:
    """Calculate workflow duration in seconds.

    Args:
        start_time: ISO 8601 formatted start time.
        end_time: ISO 8601 formatted end time.

    Returns:
        Duration in seconds.
    """
    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)
    return (end - start).total_seconds()


def build_results_table(result: dict) -> Table:
    """Build a rich table with workflow results.

    Args:
        result: Workflow result dictionary.

    Returns:
        Formatted rich Table object.
    """
    table = Table(
        title="Workflow Execution Results",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Field", style="cyan", width=15)
    table.add_column("Value", style="green")

    table.add_row("Status", result.get("status", "unknown"))

    if result.get("error"):
        table.add_row("Error", f"[red]{result['error']}[/red]")

    if result.get("end_time"):
        table.add_row("End Time", result["end_time"])
        duration = calculate_duration(result["start_time"], result["end_time"])
        table.add_row("Duration", f"{duration:.2f} seconds")

    if result.get("output_path"):
        table.add_row("Output Path", result["output_path"])

    if result.get("extension_metadata"):
        metadata = result["extension_metadata"]
        table.add_row("Metadata", json.dumps(metadata, indent=2))

    return table


def print_results(result: dict):
    """Print workflow results.

    Args:
        result: Workflow result dictionary.
    """
    table = build_results_table(result)
    console.print("\n", table)

    # Display executive summary if available
    if result.get("executive_summary"):
        console.print("\n[bold cyan]Executive Summary:[/bold cyan]")
        summary = result["executive_summary"]

        # Display overall risk level with color coding
        risk_level = summary.get("overall_risk_level", "unknown")
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(risk_level, "white")
        console.print(f"  Risk Level: [{risk_color}]{risk_level.upper()}[/{risk_color}]\n")

        # Display summary
        console.print(f"  [bold]Summary:[/bold]")
        console.print(f"  {summary.get('summary', 'N/A')}\n")

        # Display key findings
        if summary.get("key_findings"):
            console.print(f"  [bold]Key Findings:[/bold]")
            for finding in summary["key_findings"]:
                console.print(f"    • {finding}")
            console.print()

        # Display recommendations
        if summary.get("recommendations"):
            console.print(f"  [bold]Recommendations:[/bold]")
            for rec in summary["recommendations"]:
                console.print(f"    • {rec}")
            console.print()

    console.print(
        f"\n[bold green]✓[/bold green] Workflow finished for [blue]{result['chrome_extension_path']}[/blue]\n"
    )


def run_workflow(chrome_extension_path: str):
    """Run the workflow with the given Chrome extension path.

    Args:
        chrome_extension_path: Path of the Chrome extension to use in the workflow.
    """
    configure_logging()
    print_header()

    # Build the workflow graph
    graph = build_graph()

    # Create and display initial state
    initial_state = create_initial_state(chrome_extension_path=chrome_extension_path)
    print_initial_state(initial_state)

    # Execute the workflow
    with console.status("[bold green]Executing workflow...", spinner="dots"):
        result = graph.invoke(initial_state)

    # Display results
    print_results(result)


def main():
    """Main entry point."""
    # url = "https://chromewebstore.google.com/detail/allow-x-frame-options/jfjdfokifdlmbkbncmcfbcobggohdnif"
    # url = "https://chromewebstore.google.com/detail/pinterest-love-pinterest/nkabooldphfdjcbhcodblkfmigmpchhi"
    url = "https://chromewebstore.google.com/detail/steam-inventory-helper/cmeakgjggjdlcpncigglobpjbkabhmjl"
    run_workflow(chrome_extension_path=url)


if __name__ == "__main__":
    main()

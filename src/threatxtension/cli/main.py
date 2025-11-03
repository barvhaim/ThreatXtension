#!/usr/bin/env python3
"""
Command line interface for ThreatXtension - Chrome Extension Security Analysis Tool.

Usage:
    threatxtension analyze --url <chrome_web_store_url>
    threatxtension analyze --url <url> --output <output_file>
"""

import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatxtension.workflow.graph import build_graph
from threatxtension.workflow.state import WorkflowStatus


console = Console()
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool = False):
    """Configure logging for the CLI.

    Args:
        verbose: Enable verbose logging.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def print_header():
    """Print CLI header."""
    console.print(
        Panel.fit(
            "[bold cyan]ThreatXtension - Chrome Extension Security Analyzer[/bold cyan]",
            border_style="cyan",
        )
    )


def create_initial_state(chrome_extension_path: str) -> dict:
    """Create initial workflow state.

    Args:
        chrome_extension_path: Chrome Web Store URL of the extension to analyze.

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


def build_metadata_table(metadata: dict) -> Table:
    """Build a rich table with extension metadata.

    Args:
        metadata: Extension metadata dictionary.

    Returns:
        Formatted rich Table object.
    """
    table = Table(
        title="Extension Metadata",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Field", style="cyan", width=25)
    table.add_column("Value", style="white")

    # Display all available metadata fields
    field_mapping = {
        "title": "Name",
        "version": "Version",
        "user_count": "Users",
        "rating": "Rating",
        "ratings_count": "Ratings Count",
        "last_updated": "Last Updated",
        "size": "Size",
        "developer_name": "Developer Name",
        "developer_email": "Developer Email",
        "developer_website": "Developer Website",
        "follows_best_practices": "Follows Best Practices",
        "is_featured": "Featured",
        "category": "Category",
    }

    for key, label in field_mapping.items():
        value = metadata.get(key)
        if value is not None:
            # Format specific fields
            if key == "rating":
                table.add_row(label, f"{value} / 5")
            elif key == "user_count":
                table.add_row(label, f"{value:,}")
            elif key == "ratings_count":
                table.add_row(label, f"{value:,}")
            elif key == "follows_best_practices" or key == "is_featured":
                table.add_row(label, "Yes" if value else "No")
            else:
                table.add_row(label, str(value))

    # Display privacy policy (truncated if too long)
    privacy_policy = metadata.get("privacy_policy")
    if privacy_policy:
        privacy_text = str(privacy_policy)
        if len(privacy_text) > 150:
            privacy_text = privacy_text[:150] + "..."
        table.add_row("Privacy Policy", privacy_text)

    return table


def print_results(result: dict):
    """Print workflow results to console.

    Args:
        result: Workflow result dictionary.
    """
    console.print("\n")

    # Status and basic info
    status = result.get("status", "unknown")
    status_color = {"completed": "green", "failed": "red"}.get(status, "yellow")
    console.print(f"Status: [{status_color}]{status.upper()}[/{status_color}]")

    if result.get("error"):
        console.print(f"\n[red]Error: {result['error']}[/red]\n")
        return

    # Duration
    if result.get("end_time"):
        duration = calculate_duration(result["start_time"], result["end_time"])
        console.print(f"Duration: [cyan]{duration:.2f}[/cyan] seconds")

    # Extension metadata
    if result.get("extension_metadata"):
        console.print("\n")
        metadata_table = build_metadata_table(result["extension_metadata"])
        console.print(metadata_table)

    # Executive summary
    if result.get("executive_summary"):
        console.print("\n")
        console.print(Panel.fit("[bold cyan]Executive Summary[/bold cyan]", border_style="cyan"))

        summary = result["executive_summary"]

        # Risk level with color coding
        risk_level = summary.get("overall_risk_level", "unknown")
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(risk_level, "white")
        console.print(
            f"\n[bold]Risk Level:[/bold] [{risk_color}]{risk_level.upper()}[/{risk_color}]\n"
        )

        # Summary
        if summary.get("summary"):
            console.print("[bold]Summary:[/bold]")
            console.print(f"{summary['summary']}\n")

        # Key findings
        if summary.get("key_findings"):
            console.print("[bold]Key Findings:[/bold]")
            for i, finding in enumerate(summary["key_findings"], 1):
                console.print(f"  {i}. {finding}")
            console.print()

        # Recommendations
        if summary.get("recommendations"):
            console.print("[bold]Recommendations:[/bold]")
            for i, rec in enumerate(summary["recommendations"], 1):
                console.print(f"  {i}. {rec}")
            console.print()

    console.print(f"[bold green]✓[/bold green] Analysis completed\n")


def save_results_json(result: dict, output_path: Path):
    """Save workflow results to JSON file.

    Args:
        result: Workflow result dictionary.
        output_path: Path to save the JSON file.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    console.print(f"\n[green]Results saved to:[/green] {output_path}")


@click.group()
@click.version_option(version="0.1.0", prog_name="threatxtension")
def cli():
    """ThreatXtension - Chrome Extension Security Analyzer.

    Analyzes Chrome extensions for security threats using LangGraph workflows
    and LLM-powered analysis.
    """


@cli.command()
@click.option(
    "--url",
    required=True,
    help="Chrome Web Store URL of the extension to analyze",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path to save results as JSON",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
def analyze(url: str, output: Optional[str], verbose: bool):
    """Analyze a Chrome extension for security threats.

    Example:
        threatxtension analyze --url https://chromewebstore.google.com/detail/example/abcdef
    """
    configure_logging(verbose)
    print_header()

    console.print(f"\n[bold]Analyzing:[/bold] [blue]{url}[/blue]\n")

    # Build workflow graph
    graph = build_graph()

    # Create initial state
    initial_state = create_initial_state(chrome_extension_path=url)

    # Execute workflow with spinner
    try:
        with console.status("[bold green]Running analysis...", spinner="dots"):
            result = graph.invoke(initial_state)
    except Exception as e:
        console.print(f"\n[red]Analysis failed: {e}[/red]\n")
        logger.exception("Workflow execution failed")
        raise click.Abort()

    # Print results
    print_results(result)

    # Save to file if requested
    if output:
        output_path = Path(output)
        save_results_json(result, output_path)


@cli.command()
def version():
    """Show version information."""
    console.print("[cyan]ThreatXtension[/cyan] version [green]0.1.0[/green]")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()

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


def create_initial_state(chrome_extension_path: str, keep_extracted: bool = False) -> dict:
    """Create initial workflow state.

    Args:
        chrome_extension_path: Chrome Web Store URL of the extension to analyze.
        keep_extracted: Whether to retain the extracted extension directory after
            analysis. Defaults to False for the CLI, since it has no file viewer and
            leaving extracted samples on disk is unnecessary.

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
        "keep_extracted": keep_extracted,
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
            elif key in ("follows_best_practices", "is_featured"):
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


def build_virustotal_table(vt_results: dict) -> Table:
    """Build a rich table with VirusTotal analysis results.

    Args:
        vt_results: VirusTotal analysis results dictionary.

    Returns:
        Formatted rich Table object.
    """
    table = Table(
        title="VirusTotal Analysis",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="white")

    if not vt_results.get("enabled", False):
        table.add_row("Status", "[yellow]Disabled (API key not configured)[/yellow]")
        return table

    table.add_row("Files Analyzed", str(vt_results.get("files_analyzed", 0)))
    table.add_row("Files with Detections", str(vt_results.get("files_with_detections", 0)))

    total_malicious = vt_results.get("total_malicious", 0)
    total_suspicious = vt_results.get("total_suspicious", 0)

    mal_color = "red" if total_malicious > 0 else "green"
    sus_color = "yellow" if total_suspicious > 0 else "green"

    table.add_row("Malicious Detections", f"[{mal_color}]{total_malicious}[/{mal_color}]")
    table.add_row("Suspicious Detections", f"[{sus_color}]{total_suspicious}[/{sus_color}]")

    summary = vt_results.get("summary", {})
    threat_level = summary.get("threat_level", "unknown")
    threat_color = {"clean": "green", "suspicious": "yellow", "malicious": "red"}.get(
        threat_level, "white"
    )
    table.add_row("Threat Level", f"[{threat_color}]{threat_level.upper()}[/{threat_color}]")

    if summary.get("detected_families"):
        families = ", ".join(summary["detected_families"][:5])
        table.add_row("Detected Families", families)

    return table


def build_entropy_table(entropy_results: dict) -> Table:
    """Build a rich table with entropy analysis results.

    Args:
        entropy_results: Entropy analysis results dictionary.

    Returns:
        Formatted rich Table object.
    """
    table = Table(
        title="Entropy Analysis",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="white")

    table.add_row("Files Analyzed", str(entropy_results.get("files_analyzed", 0)))
    table.add_row("Files Skipped", str(entropy_results.get("files_skipped", 0)))

    obfuscated = entropy_results.get("obfuscated_files", 0)
    suspicious = entropy_results.get("suspicious_files", 0)

    obf_color = "red" if obfuscated > 0 else "green"
    sus_color = "yellow" if suspicious > 0 else "green"

    table.add_row("Obfuscated Files", f"[{obf_color}]{obfuscated}[/{obf_color}]")
    table.add_row("Suspicious Files", f"[{sus_color}]{suspicious}[/{sus_color}]")

    summary = entropy_results.get("summary", {})
    overall_risk = summary.get("overall_risk", "unknown")
    risk_color = {"normal": "green", "low": "green", "medium": "yellow", "high": "red"}.get(
        overall_risk, "white"
    )
    table.add_row("Overall Risk", f"[{risk_color}]{overall_risk.upper()}[/{risk_color}]")

    obf_detected = summary.get("obfuscation_detected", False)
    obf_status = "[red]Yes[/red]" if obf_detected else "[green]No[/green]"
    table.add_row("Obfuscation Detected", obf_status)

    # Show high entropy files if any
    high_entropy_files = summary.get("high_entropy_files", [])
    if high_entropy_files:
        files_str = ", ".join([f["file"] for f in high_entropy_files[:3]])
        table.add_row("High Entropy Files", files_str)

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

    # Analysis results section
    analysis_results = result.get("analysis_results", {})

    # VirusTotal results
    if analysis_results.get("virustotal_analysis"):
        console.print("\n")
        vt_table = build_virustotal_table(analysis_results["virustotal_analysis"])
        console.print(vt_table)

        # Print recommendation if available
        vt_summary = analysis_results["virustotal_analysis"].get("summary", {})
        if vt_summary.get("recommendation"):
            console.print(f"\n[dim]{vt_summary['recommendation']}[/dim]")

    # Entropy results
    if analysis_results.get("entropy_analysis"):
        console.print("\n")
        entropy_table = build_entropy_table(analysis_results["entropy_analysis"])
        console.print(entropy_table)

        # Print recommendation if available
        entropy_summary = analysis_results["entropy_analysis"].get("summary", {})
        if entropy_summary.get("recommendation"):
            console.print(f"\n[dim]{entropy_summary['recommendation']}[/dim]")

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

    console.print("[bold green]✓[/bold green] Analysis completed\n")


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
    help="Chrome Web Store URL of the extension to analyze",
)
@click.option(
    "--id",
    "extension_id",
    help="Chrome extension ID (32-character string, e.g., gbbilodpoldeopifonmibfboicpafpjo)",
)
@click.option(
    "--file",
    "-f",
    type=click.Path(exists=True),
    help="Local CRX or ZIP file to analyze",
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
@click.option(
    "--keep-extracted/--no-keep-extracted",
    default=False,
    help="Keep the extracted extension directory after analysis (default: remove it)",
)
def analyze(
    url: Optional[str],
    extension_id: Optional[str],
    file: Optional[str],
    output: Optional[str],
    verbose: bool,
    keep_extracted: bool,
):
    """Analyze a Chrome extension for security threats.

    Example:
        threatxtension analyze --url https://chromewebstore.google.com/detail/example/abcdef
        threatxtension analyze --id gbbilodpoldeopifonmibfboicpafpjo
        threatxtension analyze --file /path/to/extension.crx
        threatxtension analyze --file /path/to/extension.zip
    """
    # Validate input
    input_count = sum([bool(url), bool(extension_id), bool(file)])
    if input_count == 0:
        raise click.UsageError("One of --url, --id, or --file must be provided")

    if input_count > 1:
        raise click.UsageError("Only one of --url, --id, or --file can be specified")

    configure_logging(verbose)
    print_header()

    # Determine which input was provided
    if file:
        chrome_extension_path = file
        input_type = "Local file"
    elif extension_id:
        chrome_extension_path = extension_id
        input_type = "Extension ID"
    else:
        chrome_extension_path = url
        input_type = "Chrome Web Store URL"

    # This should never happen due to validation above, but satisfy type checker
    if not chrome_extension_path:
        raise click.UsageError("No extension path provided")

    console.print(f"\n[bold]Analyzing:[/bold] [blue]{chrome_extension_path}[/blue]")
    console.print(f"[dim]Input type: {input_type}[/dim]\n")

    # Build workflow graph
    graph = build_graph()

    # Create initial state
    initial_state = create_initial_state(
        chrome_extension_path=chrome_extension_path, keep_extracted=keep_extracted
    )

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
@click.option(
    "--host",
    default="0.0.0.0",
    help="Host to bind the API server to (default: 0.0.0.0)",
)
@click.option(
    "--port",
    default=8007,
    type=int,
    help="Port to bind the API server to (default: 8007)",
)
@click.option(
    "--reload",
    is_flag=True,
    help="Enable auto-reload for development",
)
def serve(host: str, port: int, reload: bool):
    """Start the FastAPI server for the web frontend.

    Example:
        threatxtension serve
        threatxtension serve --port 8080 --reload
    """
    import uvicorn

    # from threatxtension.api.main import app  # Unused import

    console.print(
        Panel.fit(
            f"[bold cyan]Starting ThreatXtension API Server[/bold cyan]\n"
            f"[white]Host:[/white] [green]{host}[/green]\n"
            f"[white]Port:[/white] [green]{port}[/green]\n"
            f"[white]Reload:[/white] [green]{'Enabled' if reload else 'Disabled'}[/green]",
            border_style="cyan",
        )
    )

    console.print(
        f"\n[bold green]✓[/bold green] Server running at [blue]http://{host}:{port}[/blue]"
    )
    console.print("[dim]Press CTRL+C to stop[/dim]\n")

    uvicorn.run(
        "threatxtension.api.main:app", host=host, port=port, reload=reload, log_level="info"
    )


@cli.command()
@click.option(
    "--input",
    "-i",
    type=click.Path(exists=True),
    required=True,
    help="Input file containing extension URLs/IDs/paths (one per line)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./batch_results",
    help="Output directory for batch results (default: ./batch_results)",
)
@click.option(
    "--parallel/--sequential",
    default=True,
    help="Process extensions in parallel or sequentially (default: parallel)",
)
@click.option(
    "--workers",
    "-w",
    type=int,
    default=4,
    help="Maximum number of parallel workers (default: 4)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
def batch(input: str, output: str, parallel: bool, workers: int, verbose: bool):
    """Process multiple extensions in batch mode.

    Example:
        threatxtension batch --input urls.txt --output results/
        threatxtension batch -i extensions.txt --parallel --workers 8
        threatxtension batch -i list.txt --sequential
    """
    from threatxtension.core.batch_processor import BatchProcessor

    configure_logging(verbose)
    print_header()

    console.print(f"\n[bold]Batch Processing[/bold]")
    console.print(f"[dim]Input file: {input}[/dim]")
    console.print(f"[dim]Output directory: {output}[/dim]")
    console.print(f"[dim]Mode: {'Parallel' if parallel else 'Sequential'}[/dim]")
    if parallel:
        console.print(f"[dim]Workers: {workers}[/dim]")
    console.print()

    # Initialize batch processor
    processor = BatchProcessor(output_dir=output)

    # Process batch
    try:
        with console.status("[bold green]Processing batch...", spinner="dots"):
            result = processor.process_from_file(
                input_file=input, parallel=parallel, max_workers=workers
            )
    except Exception as e:
        console.print(f"\n[red]Batch processing failed: {e}[/red]\n")
        logger.exception("Batch processing failed")
        raise click.Abort()

    # Display results summary
    console.print("\n")
    console.print(
        Panel.fit("[bold cyan]Batch Processing Complete[/bold cyan]", border_style="cyan")
    )

    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan", width=30)
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Batch ID", result["batch_id"])
    summary_table.add_row("Total Extensions", str(result["total_extensions"]))
    summary_table.add_row("Completed", f"[green]{result['completed']}[/green]")
    summary_table.add_row("Failed", f"[red]{result['failed']}[/red]")

    success_rate = (
        result["completed"] / result["total_extensions"] * 100
        if result["total_extensions"] > 0
        else 0
    )
    summary_table.add_row("Success Rate", f"{success_rate:.1f}%")

    # Calculate duration
    if result.get("start_time") and result.get("end_time"):
        duration = calculate_duration(result["start_time"], result["end_time"])
        summary_table.add_row("Duration", f"{duration:.2f} seconds")

    console.print("\n")
    console.print(summary_table)

    # Display report path
    if result.get("report_path"):
        console.print(f"\n[green]Batch report saved to:[/green] {result['report_path']}")

    console.print("\n[bold green]✓[/bold green] Batch processing completed\n")


@cli.command()
def version():
    """Show version information."""
    console.print("[cyan]ThreatXtension[/cyan] version [green]0.1.0[/green]")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()

"""
Workflow Node Implementations

This module contains the node functions for the extension analysis workflow.
"""

import logging
from datetime import datetime
from langgraph.graph import END
from langgraph.types import Command
from threatxtension.workflow.state import WorkflowState, WorkflowStatus
from threatxtension.core.extension_metadata import ExtensionMetadata
from threatxtension.core.extension_downloader import ExtensionDownloader
from threatxtension.core.manifest_parser import ManifestParser
from threatxtension.core.extension_analyzer import ExtensionAnalyzer
from threatxtension.core.summary_generator import SummaryGenerator
from threatxtension.utils.extension import (
    extract_extension_crx,
    cleanup_extension_dir,
    is_chrome_extension_store_url,
    is_local_extension_file,
)
from threatxtension.workflow.node_types import (
    EXTENSION_METADATA_NODE,
    EXTENSION_DOWNLOADER_NODE,
    MANIFEST_PARSER_NODE,
    EXTENSION_ANALYZER_NODE,
    SUMMARY_GENERATION_NODE,
    CLEANUP_NODE,
)


logger = logging.getLogger(__name__)


def extension_path_routing_node(state: WorkflowState) -> Command:
    """Node that routes to the appropriate next node based on Chrome extension path."""
    chrome_extension_path = state.get("chrome_extension_path")
    if not chrome_extension_path:
        raise ValueError("No Chrome extension path provided in the workflow state.")

    if is_chrome_extension_store_url(chrome_extension_path):
        return Command(goto=EXTENSION_METADATA_NODE)
    
    if is_local_extension_file(chrome_extension_path):
        # For local files, skip metadata extraction and go directly to extraction
        return Command(goto=EXTENSION_DOWNLOADER_NODE)

    return Command(
        goto=END,
        update={
            "status": WorkflowStatus.FAILED.value,
            "error": "Provided Chrome extension path is not a valid Chrome Web Store URL or local file.",
        },
    )


def extension_metadata_node(state: WorkflowState) -> Command:
    """
    Node that performs the Chrome extension metadata extraction operation.

    Args:
        state (PipelineState): The current state of the workflow.

    Returns:
        Command: A command indicating the next step in the workflow.
    """
    chrome_extension_url = state.get("chrome_extension_path")
    if not chrome_extension_url:
        raise ValueError("No Chrome extension path provided in the workflow state.")

    metadata = None

    try:
        logger.info("Extracting metadata for extension URL: %s", chrome_extension_url)
        metadata_extractor = ExtensionMetadata(extension_url=chrome_extension_url)
        metadata = metadata_extractor.fetch_metadata()
    except Exception as exc:
        logger.exception("Extension metadata extraction failed: %s", str(exc))

    return Command(
        goto=EXTENSION_DOWNLOADER_NODE,
        update={
            "extension_metadata": metadata,
        },
    )


def extension_downloader_node(state: WorkflowState) -> Command:
    """
    Node that performs the Chrome extension downloading or extraction operation.

    Args:
        state (PipelineState): The current state of the workflow.

    Returns:
        Command: A command indicating the next step in the workflow.
    """
    chrome_extension_path = state.get("chrome_extension_path")
    if not chrome_extension_path:
        raise ValueError("No Chrome extension path provided in the workflow state.")

    try:
        # Check if it's a local file or URL
        if is_local_extension_file(chrome_extension_path):
            # For local files, extract directly
            logger.info("Processing local extension file: %s", chrome_extension_path)
            extension_dir = extract_extension_crx(chrome_extension_path)
            if not extension_dir:
                raise RuntimeError("Failed to extract extension file.")
        else:
            # For URLs, download first
            downloader = ExtensionDownloader()
            extension_info = downloader.download_extension(extension_url=chrome_extension_path)
            if not extension_info or "file_path" not in extension_info:
                raise RuntimeError("Extension download returned no file.")

            # Extract the CRX
            extension_dir = extract_extension_crx(extension_info["file_path"])
            if not extension_dir:
                raise RuntimeError("Failed to extract CRX file.")

    except Exception as exc:
        logger.exception("Extension download/extract failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )

    return Command(
        goto=MANIFEST_PARSER_NODE,
        update={
            "extension_dir": extension_dir,
        },
    )


def manifest_parser_node(state: WorkflowState) -> Command:
    """
    Node that performs the manifest parsing operation.

    Args:
        state (PipelineState): The current state of the workflow.

    Returns:
        Command: A command indicating the next step in the workflow.
    """
    extension_dir = state.get("extension_dir")
    if not extension_dir:
        raise ValueError("No extension directory provided in the workflow state.")

    try:
        logger.info("Parsing manifest in extension directory: %s", extension_dir)
        manifest_parser = ManifestParser(extension_dir=extension_dir)
        manifest_data = manifest_parser.parse()
        if not manifest_data:
            raise RuntimeError("Manifest parsing returned no data.")

    except Exception as exc:
        logger.exception("Manifest parsing failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )

    return Command(
        goto=EXTENSION_ANALYZER_NODE,
        update={"manifest_data": manifest_data},
    )


def extension_analyzer_node(state: WorkflowState) -> Command:
    """
    Node that performs the Chrome extension analysis operation.

    Args:
        state (PipelineState): The current state of the workflow.

    Returns:
        Command: A command indicating the next step in the workflow.
    """
    extension_dir = state.get("extension_dir")
    if not extension_dir:
        raise ValueError("No extension directory provided in the workflow state.")

    manifest = state.get("manifest_data")
    metadata = state.get("extension_metadata")

    try:
        logger.info("Analyzing extension directory: %s", extension_dir)
        analyzer = ExtensionAnalyzer(
            extension_dir=extension_dir, manifest=manifest, metadata=metadata
        )
        analysis_results = analyzer.analyze()

    except Exception as exc:
        logger.exception("Extension analysis failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )

    return Command(
        goto=SUMMARY_GENERATION_NODE,
        update={"analysis_results": analysis_results},
    )


def summary_generation_node(state: WorkflowState) -> Command:
    """
    Node that generates executive summary from all analysis results.

    Args:
        state (WorkflowState): The current state of the workflow.

    Returns:
        Command: A command indicating the next step in the workflow.
    """
    analysis_results = state.get("analysis_results")
    manifest = state.get("manifest_data")

    if not analysis_results:
        logger.warning("No analysis results available for summary generation")
        return Command(
            goto=CLEANUP_NODE,
            update={"executive_summary": None},
        )

    try:
        logger.info("Generating executive summary")
        generator = SummaryGenerator()
        executive_summary = generator.generate(analysis_results=analysis_results, manifest=manifest)

    except Exception as exc:
        logger.exception("Summary generation failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )

    return Command(
        goto=CLEANUP_NODE,
        update={"executive_summary": executive_summary},
    )


def cleanup_node(state: WorkflowState) -> Command:
    """
    Node that performs cleanup operations after the workflow is completed.

    Args:
        state (PipelineState): The current state of the workflow.
    Returns:
        Command: A command indicating the next step in the workflow.
    """
    extension_dir = state.get("extension_dir")
    if extension_dir:
        try:
            logger.info("Cleaning up extension directory: %s", extension_dir)
            cleanup_extension_dir(extension_dir)
        except Exception as exc:
            logger.warning("Failed to cleanup extension dir %s: %s", extension_dir, exc)
            return Command(
                goto=END,
                update={
                    "status": WorkflowStatus.FAILED.value,
                    "error": f"Failed to cleanup extension dir: {exc}",
                },
            )

    return Command(
        goto=END,
        update={
            "status": WorkflowStatus.COMPLETED.value,
            "end_time": datetime.now().isoformat(),
        },
    )

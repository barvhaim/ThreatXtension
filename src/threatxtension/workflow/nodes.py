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
    cleanup_downloaded_crx,
    is_chrome_extension_store_url,
    is_local_extension_crx_file,
    is_chrome_extension_id,
)
from threatxtension.core.chromestats_downloader import ChromeStatsDownloader
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

    # Check if it's an extension ID (32-character string)
    if is_chrome_extension_id(chrome_extension_path):
        logger.info("Detected Chrome extension ID: %s", chrome_extension_path)
        return Command(goto="chromestats_downloader_node")

    # Check if it's a Chrome Web Store URL
    if is_chrome_extension_store_url(chrome_extension_path):
        return Command(goto=EXTENSION_METADATA_NODE)

    # Check if it's a local CRX/ZIP file
    if is_local_extension_crx_file(chrome_extension_path):
        return Command(goto=EXTENSION_DOWNLOADER_NODE)

    return Command(
        goto=END,
        update={
            "status": WorkflowStatus.FAILED.value,
            "error": "Invalid input: not a Chrome Web Store URL, extension ID, or local CRX file.",
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
        
        # Also fetch chrome-stats metadata if we have an extension ID
        if metadata and metadata.get("extension_id"):
            try:
                logger.info("Fetching chrome-stats metadata for extension ID: %s", metadata["extension_id"])
                chromestats = ChromeStatsDownloader()
                chromestats_details = chromestats._get_extension_details(metadata["extension_id"])
                
                if chromestats_details:
                    # Add chrome_stats field to metadata
                    metadata["chrome_stats"] = chromestats_details
                    logger.info("Successfully fetched chrome-stats metadata")
                else:
                    logger.warning("No chrome-stats metadata available for extension ID: %s", metadata["extension_id"])
            except Exception as chromestats_exc:
                logger.warning("Failed to fetch chrome-stats metadata: %s", chromestats_exc)
                # Don't fail the whole workflow if chrome-stats fetch fails
                
    except Exception as exc:
        logger.exception("Extension metadata extraction failed: %s", str(exc))

    return Command(
        goto=EXTENSION_DOWNLOADER_NODE,
        update={
            "extension_metadata": metadata,
        },
    )


def chromestats_downloader_node(state: WorkflowState) -> Command:
    """
    Node that downloads extension from chrome-stats.com using extension ID.
    
    Args:
        state (WorkflowState): The current state of the workflow.
        
    Returns:
        Command: A command indicating the next step in the workflow.
    """
    chrome_extension_path = state.get("chrome_extension_path")
    if not chrome_extension_path:
        raise ValueError("No Chrome extension ID provided in the workflow state.")
    
    extension_id = chrome_extension_path.strip().lower()
    downloaded_crx_path = None
    extension_dir = None
    
    try:
        logger.info("Downloading extension from chrome-stats.com: %s", extension_id)
        downloader = ChromeStatsDownloader()
        
        # Download extension (as ZIP for easier extraction)
        file_path, metadata = downloader.download_extension(
            extension_id=extension_id,
            file_format="ZIP"
        )
        
        if not file_path or not metadata:
            raise RuntimeError("Failed to download extension from chrome-stats.com")
        
        logger.info("Successfully downloaded extension: %s", file_path)
        downloaded_crx_path = file_path
        
        # Extract the downloaded file
        extension_dir = extract_extension_crx(file_path)
        if not extension_dir:
            raise RuntimeError("Failed to extract downloaded extension")
        
        logger.info("Successfully extracted extension to: %s", extension_dir)
        
    except Exception as exc:
        logger.exception("Chrome Stats download/extract failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "extension_dir": extension_dir,
                "downloaded_crx_path": downloaded_crx_path,
                "extension_metadata": metadata if 'metadata' in locals() else None,
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )
    
    return Command(
        goto=MANIFEST_PARSER_NODE,
        update={
            "extension_dir": extension_dir,
            "downloaded_crx_path": downloaded_crx_path,
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

    downloaded_crx_path = None  # Track downloaded files for cleanup

    try:
        if is_local_extension_crx_file(chrome_extension_path):
            # User-provided file - don't set downloaded_crx_path (don't delete)
            logger.info("Processing local extension file: %s", chrome_extension_path)
            extension_dir = extract_extension_crx(chrome_extension_path)
            if not extension_dir:
                raise RuntimeError("Failed to extract extension file.")
        else:
            # Tool download - set downloaded_crx_path for cleanup
            downloader = ExtensionDownloader()
            extension_info = downloader.download_extension(extension_url=chrome_extension_path)
            if not extension_info or "file_path" not in extension_info:
                raise RuntimeError("Extension download returned no file.")

            downloaded_crx_path = extension_info["file_path"]  # Store for cleanup
            extension_dir = extract_extension_crx(downloaded_crx_path)
            if not extension_dir:
                raise RuntimeError("Failed to extract CRX file.")

    except Exception as exc:
        logger.exception("Extension download/extract failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "extension_dir": extension_dir if "extension_dir" in locals() else None,
                "downloaded_crx_path": downloaded_crx_path,
                "status": WorkflowStatus.FAILED.value,
                "error": str(exc),
            },
        )

    return Command(
        goto=MANIFEST_PARSER_NODE,
        update={
            "extension_dir": extension_dir,
            "downloaded_crx_path": downloaded_crx_path,
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
    Collects file list but KEEPS extracted directory for file viewing.
    Only removes downloaded CRX files.

    Args:
        state (PipelineState): The current state of the workflow.
    Returns:
        Command: A command indicating the next step in the workflow.
    """
    cleanup_errors = []

    # Collect file list (if not already collected)
    extension_dir = state.get("extension_dir")
    extracted_files = state.get("extracted_files", [])

    if extension_dir and not extracted_files:
        try:
            import os

            files = []
            if os.path.exists(extension_dir):
                for root, _, filenames in os.walk(extension_dir):
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        rel_path = os.path.relpath(file_path, extension_dir)
                        files.append(rel_path)
                extracted_files = files
                logger.info("Collected %d files for viewing", len(files))
        except Exception as exc:
            logger.warning("Failed to collect file list: %s", exc)

    # Retain the extracted directory only when a caller opts in (e.g. the web UI
    # file viewer); otherwise remove it. The CRX is cleaned up below regardless.
    keep_extracted = state.get("keep_extracted", False)
    if extension_dir:
        if keep_extracted:
            logger.info("Keeping extension directory for file viewing: %s", extension_dir)
        else:
            try:
                logger.info("Cleaning up extracted extension directory: %s", extension_dir)
                cleanup_extension_dir(extension_dir)
            except Exception as exc:
                logger.warning(
                    "Failed to cleanup extension directory %s: %s", extension_dir, exc
                )
                cleanup_errors.append(f"Failed to cleanup extension directory: {exc}")

    # Clean up downloaded CRX file (only if downloaded by the tool)
    downloaded_crx_path = state.get("downloaded_crx_path")
    if downloaded_crx_path:
        try:
            logger.info("Cleaning up downloaded CRX file: %s", downloaded_crx_path)
            cleanup_downloaded_crx(downloaded_crx_path)
        except Exception as exc:
            logger.warning("Failed to cleanup CRX file %s: %s", downloaded_crx_path, exc)
            cleanup_errors.append(f"Failed to cleanup CRX file: {exc}")

    # Log warnings but don't fail the workflow
    if cleanup_errors:
        logger.warning("Cleanup completed with warnings: %s", "; ".join(cleanup_errors))

    # Preserve FAILED status if already set, otherwise mark as COMPLETED
    current_status = state.get("status")
    final_status = (
        current_status
        if current_status == WorkflowStatus.FAILED.value
        else WorkflowStatus.COMPLETED.value
    )

    return Command(
        goto=END,
        update={
            "status": final_status,
            "end_time": datetime.now().isoformat(),
            "extracted_files": extracted_files,
        },
    )

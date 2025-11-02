"""
Workflow Graph Builder

This module constructs the LangGraph workflow for extension analysis.
"""

from langgraph.graph import StateGraph
from threatxtension.workflow.nodes import (
    extension_path_routing_node,
    extension_metadata_node,
    extension_downloader_node,
    manifest_parser_node,
    extension_analyzer_node,
    summary_generation_node,
    cleanup_node,
)
from threatxtension.workflow.node_types import (
    EXTENSION_PATH_ROUTING_NODE,
    EXTENSION_METADATA_NODE,
    EXTENSION_DOWNLOADER_NODE,
    MANIFEST_PARSER_NODE,
    EXTENSION_ANALYZER_NODE,
    SUMMARY_GENERATION_NODE,
    CLEANUP_NODE,
)
from threatxtension.workflow.state import WorkflowState


def build_graph():
    """Build and compile the workflow graph."""
    flow = StateGraph(WorkflowState)

    flow.add_node(EXTENSION_PATH_ROUTING_NODE, extension_path_routing_node)
    flow.add_node(EXTENSION_METADATA_NODE, extension_metadata_node)
    flow.add_node(EXTENSION_DOWNLOADER_NODE, extension_downloader_node)
    flow.add_node(MANIFEST_PARSER_NODE, manifest_parser_node)
    flow.add_node(EXTENSION_ANALYZER_NODE, extension_analyzer_node)
    flow.add_node(SUMMARY_GENERATION_NODE, summary_generation_node)
    flow.add_node(CLEANUP_NODE, cleanup_node)

    flow.set_entry_point(EXTENSION_PATH_ROUTING_NODE)

    return flow.compile()

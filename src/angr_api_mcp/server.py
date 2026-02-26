"""MCP server exposing angr API workflow retrieval tools."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from angr_api_mcp.config import Config
from angr_api_mcp.indexer.search import WorkflowSearcher

# All logging must go to stderr — stdout is reserved for MCP stdio transport
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

mcp = FastMCP("angr-workflow")

# Lazy-initialized searcher (created on first tool call)
_searcher: WorkflowSearcher | None = None


def _get_searcher() -> WorkflowSearcher:
    global _searcher
    if _searcher is None:
        config = Config()
        _searcher = WorkflowSearcher(config.db_path)
    return _searcher


@mcp.tool()
def get_workflows(task_description: str) -> str:
    """Search for angr API workflows matching a task description.

    Returns ranked workflow call chains showing the correct API call
    sequence for the described task. Each result includes ordered API
    calls with data-flow dependencies and source code.

    Args:
        task_description: Natural language description of what you want
                          to accomplish, e.g. "run CFG analysis on a binary"
    """
    searcher = _get_searcher()
    results = searcher.search_workflows(task_description, n_results=3)

    if not results:
        return "No matching workflows found. Run initialize_index() first if the index is empty."

    output_parts = []
    for i, r in enumerate(results, 1):
        output_parts.append(f"=== Result {i} (trust: {r.get('trust_level', '?')}) ===")
        output_parts.append(r.get("display_text", "(no display text)"))
        snippet = r.get("source_snippet", "")
        if snippet:
            output_parts.append(f"\nSource code:\n```python\n{snippet}\n```")
        output_parts.append("")

    return "\n".join(output_parts)


@mcp.tool()
def get_api_doc(name: str) -> str:
    """Look up angr API documentation for a class or method.

    Supports fuzzy and partial matching.

    Args:
        name: Class name, method name, or keyword to search for.
              Examples: "SimulationManager", "explore", "CFGFast", "solver"
    """
    searcher = _get_searcher()
    results = searcher.get_api_doc(name, n_results=5)

    if not results:
        return f"No API documentation found for '{name}'."

    output_parts = []
    for r in results:
        class_name = r.get("class_name", "?")
        methods = r.get("methods", "").split(",")
        workflow_count = r.get("workflow_count", 0)
        example_file = r.get("example_file", "")

        output_parts.append(f"## {class_name}")
        output_parts.append(f"Methods: {', '.join(methods)}")
        output_parts.append(f"Used in {workflow_count} extracted workflow(s)")
        if example_file:
            output_parts.append(f"Example: {example_file}")
        output_parts.append("")

    return "\n".join(output_parts)


@mcp.tool()
def list_related_apis(name: str) -> str:
    """Find angr APIs commonly used alongside a given class or method.

    Returns co-occurring APIs based on real usage patterns in angr source.

    Args:
        name: An angr class or method name, e.g. "SimulationManager"
    """
    searcher = _get_searcher()
    result = searcher.list_related_apis(name)

    if not result["related"]:
        return f"No related APIs found for '{name}'."

    output_parts = [
        f"APIs commonly used with {result['queried']} "
        f"(found in {result['workflow_count']} workflow(s)):",
        "",
    ]
    for item in result["related"]:
        output_parts.append(
            f"- {item['class']}: co-occurs in {item['co_occurrence_count']} workflow(s)"
        )

    return "\n".join(output_parts)


@mcp.tool()
def get_index_info() -> str:
    """Return metadata about the currently built index.

    Shows the angr version the index was built from, when it was indexed,
    and how many workflows and API classes are stored.
    """
    from angr_api_mcp.indexer.store import get_client
    from angr_api_mcp.indexer.store import get_index_info as _get_info

    config = Config()
    info = _get_info(get_client(config.db_path))

    if info["workflow_count"] == 0 and info["angr_version"] == "unknown":
        return "Index is empty. Run initialize_index() to build it."

    return (
        f"angr version  : {info['angr_version']}\n"
        f"Indexed at    : {info['indexed_at']}\n"
        f"Workflows     : {info['workflow_count']}\n"
        f"API classes   : {info['api_class_count']}"
    )


@mcp.tool()
def clear_index() -> str:
    """Delete the workflow index (ChromaDB collections).

    Removes all indexed data. You will need to run initialize_index() again
    before the query tools return results.
    """
    from angr_api_mcp.indexer.store import clear_index as _clear
    from angr_api_mcp.indexer.store import get_client

    config = Config()
    _clear(get_client(config.db_path))

    global _searcher
    _searcher = None

    return "Index cleared. Run initialize_index() to rebuild."


@mcp.tool()
def initialize_index(angr_path: str = "", angr_doc_path: str = "") -> str:
    """Build the angr API workflow index (RAG database).

    Clones angr and angr-doc from GitHub (or uses local copies) and builds
    the searchable workflow index. Must be run once before the other tools
    return results.

    WARNING: This is a long-running operation. Cloning repos and processing
    source files may take several minutes depending on network and CPU speed.

    Args:
        angr_path: Optional absolute path to a local angr source tree.
                   Leave empty to clone from GitHub automatically.
        angr_doc_path: Optional absolute path to a local angr-doc tree.
                       Leave empty to clone from GitHub automatically.
    """
    from angr_api_mcp.pipeline import build_index_pipeline

    messages: list[str] = []
    build_index_pipeline(
        angr_path=Path(angr_path) if angr_path else None,
        angr_doc_path=Path(angr_doc_path) if angr_doc_path else None,
        progress=messages.append,
    )

    global _searcher
    _searcher = None

    return "\n".join(messages)


def run_server():
    """Start the MCP server with stdio transport."""
    mcp.run(transport="stdio")

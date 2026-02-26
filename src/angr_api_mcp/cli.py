"""CLI entry points for the angr API MCP server."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from angr_api_mcp.config import DEFAULT_DB_PATH

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


@click.group()
def main():
    """angr API Workflow Retrieval MCP Server."""


@main.command("build-index")
@click.option(
    "--angr-path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a local angr source tree. If not provided, angr will be cloned.",
)
@click.option(
    "--angr-doc-path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a local angr-doc tree. If not provided, angr-doc will be cloned.",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=lambda: str(DEFAULT_DB_PATH),
    show_default=True,
    help="Path for ChromaDB storage.",
)
@click.option(
    "--max-files",
    type=int,
    default=None,
    help="Limit the number of Python files to process (for testing).",
)
def build_index(
    angr_path: Path | None,
    angr_doc_path: Path | None,
    db_path: Path,
    max_files: int | None,
):
    """Build the workflow index from angr source code."""
    from angr_api_mcp.pipeline import build_index_pipeline

    build_index_pipeline(
        angr_path=angr_path,
        angr_doc_path=angr_doc_path,
        db_path=db_path,
        max_files=max_files,
        progress=click.echo,
    )


@main.command("clear-index")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=lambda: str(DEFAULT_DB_PATH),
    show_default=True,
    help="Path to ChromaDB storage.",
)
def clear_index(db_path: Path):
    """Delete the workflow index without rebuilding."""
    from angr_api_mcp.indexer.store import clear_index as _clear
    from angr_api_mcp.indexer.store import get_client

    _clear(get_client(db_path))
    click.echo("Index cleared.")


@main.command()
def serve():
    """Start the MCP server (stdio transport)."""
    from angr_api_mcp.server import run_server

    run_server()


_DB_PATH_OPTION = click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=lambda: str(DEFAULT_DB_PATH),
    show_default=True,
    help="Path to ChromaDB storage.",
)


@main.group()
def inspect():
    """Test MCP tools against the index without running the server."""


@inspect.command("info")
@_DB_PATH_OPTION
def inspect_info(db_path: Path):
    """Show index metadata: angr version, build time, counts."""
    from angr_api_mcp.indexer.store import get_client
    from angr_api_mcp.indexer.store import get_index_info

    info = get_index_info(get_client(db_path))

    if info["workflow_count"] == 0 and info["angr_version"] == "unknown":
        click.echo("Index is empty. Run build-index to populate it.")
        return

    click.echo(f"angr version  : {info['angr_version']}")
    click.echo(f"Indexed at    : {info['indexed_at']}")
    click.echo(f"Workflows     : {info['workflow_count']}")
    click.echo(f"API classes   : {info['api_class_count']}")


@inspect.command("workflows")
@click.argument("query")
@_DB_PATH_OPTION
@click.option(
    "--n-results",
    type=int,
    default=3,
    show_default=True,
    help="Number of results to return.",
)
def inspect_workflows(query: str, db_path: Path, n_results: int):
    """Search for API workflows matching a task description."""
    from angr_api_mcp.indexer.search import WorkflowSearcher

    searcher = WorkflowSearcher(db_path)
    results = searcher.search_workflows(query, n_results=n_results)

    if not results:
        click.echo("No results found.")
        return

    for i, r in enumerate(results, 1):
        click.echo(f"=== Result {i} (trust: {r.get('trust_level', '?')}) ===")
        click.echo(r.get("display_text", "(no display text)"))
        snippet = r.get("source_snippet", "")
        if snippet:
            click.echo(f"\nSource code:\n```python\n{snippet}\n```")
        click.echo(f"\nSource: {r.get('file_path', '?')}")
        click.echo("---")


@inspect.command("api-doc")
@click.argument("name")
@_DB_PATH_OPTION
@click.option(
    "--n-results",
    type=int,
    default=5,
    show_default=True,
    help="Number of results to return.",
)
def inspect_api_doc(name: str, db_path: Path, n_results: int):
    """Look up an angr class or method."""
    from angr_api_mcp.indexer.search import WorkflowSearcher

    searcher = WorkflowSearcher(db_path)
    results = searcher.get_api_doc(name, n_results=n_results)

    if not results:
        click.echo(f"No API documentation found for '{name}'.")
        return

    for r in results:
        class_name = r.get("class_name", "?")
        methods = r.get("methods", "").split(",")
        workflow_count = r.get("workflow_count", 0)
        example_file = r.get("example_file", "")

        click.echo(f"## {class_name}")
        click.echo(f"Methods: {', '.join(methods)}")
        click.echo(f"Used in {workflow_count} extracted workflow(s)")
        if example_file:
            click.echo(f"Example: {example_file}")
        click.echo("---")


@inspect.command("related")
@click.argument("name")
@_DB_PATH_OPTION
def inspect_related(name: str, db_path: Path):
    """Find APIs commonly used alongside a class."""
    from angr_api_mcp.indexer.search import WorkflowSearcher

    searcher = WorkflowSearcher(db_path)
    result = searcher.list_related_apis(name)

    if not result["related"]:
        click.echo(f"No related APIs found for '{name}'.")
        return

    click.echo(
        f"APIs commonly used with {result['queried']} "
        f"(found in {result['workflow_count']} workflow(s)):"
    )
    for item in result["related"]:
        click.echo(
            f"  {item['class']}: co-occurs in {item['co_occurrence_count']} workflow(s)"
        )


if __name__ == "__main__":
    main()

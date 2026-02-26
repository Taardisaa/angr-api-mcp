"""Shared pipeline for building the angr workflow index."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from angr_api_mcp.config import Config


def build_index_pipeline(
    angr_path: Path | None = None,
    angr_doc_path: Path | None = None,
    db_path: Path = Path("data/chroma_db"),
    max_files: int | None = None,
    progress: Callable[[str], None] = lambda _: None,
) -> None:
    """Run the full index-build pipeline.

    Args:
        angr_path: Path to a local angr source tree. If None, angr is cloned
                   from GitHub.
        angr_doc_path: Path to a local angr-doc tree. If None, angr-doc is
                       cloned from GitHub.
        db_path: Directory for ChromaDB persistent storage.
        max_files: Limit files processed (useful for testing).
        progress: Callable invoked with each status message.
    """
    from angr_api_mcp.collector.angr_source import (
        build_known_angr_classes,
        clone_repo,
        detect_angr_version,
        enumerate_python_files,
        validate_angr_doc_root,
        validate_angr_root,
    )
    from angr_api_mcp.extractor.call_chain import extract_workflows_from_source
    from angr_api_mcp.indexer.store import (
        build_api_class_index,
        build_workflow_index,
        get_client,
    )

    config = Config(
        angr_source_path=angr_path,
        angr_doc_path=angr_doc_path,
        db_path=db_path,
        max_files=max_files,
    )

    # --- Resolve angr source ---
    if config.angr_source_path and validate_angr_root(config.angr_source_path):
        angr_root: Path | None = config.angr_source_path
    else:
        angr_root = clone_repo(
            config.angr_clone_url,
            Path("data/angr_source"),
            config.clone_depth,
        )
    progress(f"Using angr source at: {angr_root}")

    # --- Resolve angr-doc source ---
    if config.angr_doc_path and validate_angr_doc_root(config.angr_doc_path):
        angr_doc_root: Path | None = config.angr_doc_path
    else:
        try:
            angr_doc_root = clone_repo(
                config.angr_doc_clone_url,
                Path("data/angr_doc_source"),
                config.clone_depth,
            )
        except Exception as e:
            progress(f"Warning: could not clone angr-doc ({e}); skipping examples")
            angr_doc_root = None

    if angr_doc_root:
        progress(f"Using angr-doc source at: {angr_doc_root}")

    # --- Detect version ---
    angr_version = detect_angr_version(angr_root) if angr_root else "unknown"
    progress(f"angr version: {angr_version}")

    # --- Build known class set ---
    progress("Scanning for known angr class names...")
    known_classes = (
        build_known_angr_classes(angr_root)
        if angr_root else set()
    )
    # Merge with baseline to ensure essential classes are always present
    known_classes |= config.known_classes_baseline
    progress(f"Found {len(known_classes)} known angr classes")

    # --- Enumerate Python files ---
    progress("Enumerating Python source files...")
    source_files = enumerate_python_files(angr_root, angr_doc_root, config)
    progress(f"Found {len(source_files)} Python files to process")

    # --- Extract workflows ---
    progress("Extracting workflows...")
    all_workflows = []
    for i, sf in enumerate(source_files):
        if (i + 1) % 500 == 0:
            progress(f"  Processed {i + 1}/{len(source_files)} files...")
        wfs = extract_workflows_from_source(sf, known_classes, config)
        all_workflows.extend(wfs)
    progress(f"Extracted {len(all_workflows)} workflows")

    # --- Build ChromaDB index ---
    progress("Building ChromaDB index...")
    client = get_client(config.db_path)
    build_workflow_index(client, all_workflows, angr_version=angr_version)
    build_api_class_index(client, all_workflows)
    progress(f"Index built at: {config.db_path}")
    progress("Done!")

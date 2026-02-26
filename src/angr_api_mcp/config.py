"""Configuration for the angr API MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_db_path() -> Path:
    """Return a stable user-data directory that survives across uvx/pip installs."""
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "angr-api-mcp" / "chroma_db"
    return Path.home() / ".local" / "share" / "angr-api-mcp" / "chroma_db"


DEFAULT_DB_PATH: Path = _default_db_path()


@dataclass
class Config:
    angr_source_path: Path | None = None
    angr_doc_path: Path | None = None
    db_path: Path = field(default_factory=_default_db_path)
    angr_clone_url: str = "https://github.com/angr/angr.git"
    angr_doc_clone_url: str = "https://github.com/angr/angr-doc.git"
    clone_depth: int = 1
    max_files: int | None = None  # None = no limit
    search_results_default: int = 5

    # Scan directories ordered by trust/priority.
    # Each tuple: (repo_key, glob_pattern, trust_level, category)
    # repo_key: "angr_doc" | "angr"
    scan_dirs: list[tuple[str, str, str, str]] = field(default_factory=lambda: [
        ("angr_doc", "examples/",  "highest", "example"),
        ("angr",     "tests/",     "high",    "test"),
        ("angr",     "angr/",      "medium",  "main_source"),
    ])

    # Property/factory chain → return type table.
    # Key: "ClassName.property_name"
    # Value: returned class name
    angr_property_return_types: dict[str, str] = field(default_factory=lambda: {
        "Project.factory":                        "AngrObjectFactory",
        "Project.analyses":                       "Analyses",
        "Project.loader":                         "Loader",
        "Project.kb":                             "KnowledgeBase",
        "AngrObjectFactory.simulation_manager":   "SimulationManager",
        "AngrObjectFactory.entry_state":          "SimState",
        "AngrObjectFactory.blank_state":          "SimState",
        "AngrObjectFactory.full_init_state":      "SimState",
        "AngrObjectFactory.call_state":           "SimState",
        "AngrObjectFactory.block":                "Block",
        "AngrObjectFactory.path":                 "Path",
        "SimState.solver":                        "Solver",
        "SimState.memory":                        "SimMemory",
        "SimState.regs":                          "Registers",
        "SimState.posix":                         "SimSystemPosix",
        "SimState.history":                       "SimStateHistory",
        "SimulationManager.one_active":           "SimState",
        "SimulationManager.deadended":            "SimState",
        "SimulationManager.found":                "SimState",
        "Loader.main_object":                     "Backend",
    })

    # Baseline known angr class names (used before the dynamic scan completes).
    known_classes_baseline: frozenset[str] = field(default_factory=lambda: frozenset({
        "Project", "SimulationManager", "SimState",
        "CFGFast", "CFGEmulated", "CFGBase",
        "VFG", "DDG", "CDG", "BackwardSlice", "RDA",
        "SimProcedure", "ExplorationTechnique",
        "AngrObjectFactory", "KnowledgeBase",
        "Block", "Loader", "Backend",
        "Solver", "SimMemory", "SimSystemPosix",
        "BVV", "BVS", "Registers",
        "Hook", "SIM_PROCEDURES",
    }))

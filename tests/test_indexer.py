"""Tests for ChromaDB ingestion and search."""

from __future__ import annotations

from pathlib import Path

import pytest

from angr_api_mcp.config import Config
from angr_api_mcp.extractor.call_chain import extract_workflows_from_source
from angr_api_mcp.extractor.models import SourceFile, TrustLevel
from angr_api_mcp.indexer.search import WorkflowSearcher
from angr_api_mcp.indexer.store import (
    build_api_class_index,
    build_workflow_index,
    clear_index,
    get_client,
    get_index_info,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONFIG = Config()
KNOWN_CLASSES = CONFIG.known_classes_baseline | {
    "Project", "SimulationManager", "SimState", "CFGFast",
    "AngrObjectFactory", "Solver", "Block",
}


def _all_fixture_workflows() -> list:
    workflows = []
    for name in ("basic_cfg.py", "symbolic_exec.py", "state_manipulation.py"):
        sf = SourceFile(
            path=FIXTURES_DIR / name,
            trust_level=TrustLevel.HIGH,
            category="test",
        )
        workflows.extend(extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG))
    return workflows


@pytest.fixture
def populated_db(tmp_path):
    """A temporary ChromaDB with fixture workflows indexed."""
    client = get_client(tmp_path)
    workflows = _all_fixture_workflows()
    build_workflow_index(client, workflows, angr_version="test-0.1")
    build_api_class_index(client, workflows)
    return tmp_path


class TestIndexInfo:
    def test_empty_db_returns_defaults(self, tmp_path):
        client = get_client(tmp_path)
        info = get_index_info(client)
        assert info["workflow_count"] == 0
        assert info["angr_version"] == "unknown"

    def test_populated_db_has_workflows(self, populated_db):
        client = get_client(populated_db)
        info = get_index_info(client)
        assert info["workflow_count"] > 0
        assert info["angr_version"] == "test-0.1"
        assert info["indexed_at"] != "unknown"

    def test_populated_db_has_classes(self, populated_db):
        client = get_client(populated_db)
        info = get_index_info(client)
        assert info["api_class_count"] > 0


class TestClearIndex:
    def test_clear_empties_db(self, populated_db):
        client = get_client(populated_db)
        clear_index(client)
        info = get_index_info(client)
        assert info["workflow_count"] == 0

    def test_clear_on_empty_db_is_safe(self, tmp_path):
        client = get_client(tmp_path)
        clear_index(client)  # Should not raise


class TestWorkflowSearch:
    def test_search_returns_results(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.search_workflows("CFG analysis", n_results=3)
        assert len(results) >= 1

    def test_search_returns_display_text(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.search_workflows("symbolic execution explore", n_results=3)
        assert results
        assert "display_text" in results[0]

    def test_search_empty_db_returns_empty(self, tmp_path):
        searcher = WorkflowSearcher(tmp_path)
        results = searcher.search_workflows("anything")
        assert results == []

    def test_trust_level_in_metadata(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.search_workflows("project binary analysis", n_results=5)
        assert results
        assert "trust_level" in results[0]


class TestApiDocLookup:
    def test_exact_class_lookup(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.get_api_doc("Project")
        assert results
        assert results[0]["class_name"] == "Project"

    def test_fuzzy_lookup(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.get_api_doc("simulation manager symbolic")
        assert results

    def test_methods_in_result(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        results = searcher.get_api_doc("Project")
        assert results
        assert "methods" in results[0]
        assert results[0]["methods"]  # non-empty


class TestRelatedApis:
    def test_related_returns_results(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        result = searcher.list_related_apis("Project")
        assert result["queried"] == "Project"
        assert result["workflow_count"] >= 1
        assert isinstance(result["related"], list)

    def test_related_unknown_class(self, populated_db):
        searcher = WorkflowSearcher(populated_db)
        result = searcher.list_related_apis("NonExistentClass")
        assert result["related"] == []
        assert result["workflow_count"] == 0

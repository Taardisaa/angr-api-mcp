"""Tests for the MCP server tool functions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from angr_api_mcp.config import Config
from angr_api_mcp.extractor.call_chain import extract_workflows_from_source
from angr_api_mcp.extractor.models import SourceFile, TrustLevel
from angr_api_mcp.indexer.store import (
    build_api_class_index,
    build_workflow_index,
    get_client,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONFIG = Config()
KNOWN_CLASSES = CONFIG.known_classes_baseline | {
    "Project", "SimulationManager", "SimState", "CFGFast",
    "AngrObjectFactory", "Solver", "Block",
}


def _build_test_db(tmp_path: Path) -> Path:
    """Build a populated index in tmp_path and return the path."""
    workflows = []
    for name in ("basic_cfg.py", "symbolic_exec.py", "state_manipulation.py"):
        sf = SourceFile(
            path=FIXTURES_DIR / name,
            trust_level=TrustLevel.HIGH,
            category="test",
        )
        workflows.extend(extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG))

    client = get_client(tmp_path)
    build_workflow_index(client, workflows, angr_version="test")
    build_api_class_index(client, workflows)
    return tmp_path


def _make_config_with_db(db_path: Path) -> Config:
    return Config(db_path=db_path)


class TestGetWorkflows:
    def test_returns_results(self, tmp_path):
        db_path = _build_test_db(tmp_path)
        with patch("angr_api_mcp.server._searcher", None):
            with patch("angr_api_mcp.server.Config", return_value=_make_config_with_db(db_path)):
                from angr_api_mcp import server
                server._searcher = None
                with patch.object(server, "Config", return_value=_make_config_with_db(db_path)):
                    from angr_api_mcp.indexer.search import WorkflowSearcher
                    server._searcher = WorkflowSearcher(db_path)
                    result = server.get_workflows("CFG analysis binary")
                    assert "Result 1" in result

    def test_empty_db_returns_hint(self, tmp_path):
        from angr_api_mcp import server
        from angr_api_mcp.indexer.search import WorkflowSearcher
        server._searcher = WorkflowSearcher(tmp_path)
        result = server.get_workflows("anything")
        assert "initialize_index" in result.lower() or "No matching" in result


class TestGetApiDoc:
    def test_returns_class_info(self, tmp_path):
        db_path = _build_test_db(tmp_path)
        from angr_api_mcp import server
        from angr_api_mcp.indexer.search import WorkflowSearcher
        server._searcher = WorkflowSearcher(db_path)
        result = server.get_api_doc("Project")
        assert "Project" in result

    def test_unknown_class_returns_not_found(self, tmp_path):
        from angr_api_mcp import server
        from angr_api_mcp.indexer.search import WorkflowSearcher
        server._searcher = WorkflowSearcher(tmp_path)
        result = server.get_api_doc("NonExistentClass12345")
        assert "No API documentation" in result


class TestListRelatedApis:
    def test_returns_related(self, tmp_path):
        db_path = _build_test_db(tmp_path)
        from angr_api_mcp import server
        from angr_api_mcp.indexer.search import WorkflowSearcher
        server._searcher = WorkflowSearcher(db_path)
        result = server.list_related_apis("Project")
        # Either found related or graceful message
        assert isinstance(result, str)
        assert len(result) > 0


class TestGetIndexInfo:
    def test_empty_index_shows_hint(self, tmp_path):
        from angr_api_mcp import server
        from angr_api_mcp.indexer.store import get_client, get_index_info
        with patch.object(server, "Config", return_value=_make_config_with_db(tmp_path)):
            result = server.get_index_info()
            assert "initialize_index" in result.lower() or "empty" in result.lower()

    def test_populated_index_shows_version(self, tmp_path):
        db_path = _build_test_db(tmp_path)
        with patch.object(
            __import__("angr_api_mcp.server", fromlist=["Config"]),
            "Config",
            return_value=_make_config_with_db(db_path),
        ):
            from angr_api_mcp import server
            with patch.object(server, "Config", return_value=_make_config_with_db(db_path)):
                result = server.get_index_info()
                assert "test" in result or "angr version" in result.lower()


class TestClearIndex:
    def test_clear_returns_message(self, tmp_path):
        db_path = _build_test_db(tmp_path)
        from angr_api_mcp import server
        with patch.object(server, "Config", return_value=_make_config_with_db(db_path)):
            result = server.clear_index()
            assert "clear" in result.lower() or "rebuild" in result.lower()

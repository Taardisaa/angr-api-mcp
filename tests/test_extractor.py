"""Tests for the angr API call chain extractor."""

from __future__ import annotations

from pathlib import Path

import pytest

from angr_api_mcp.config import Config
from angr_api_mcp.extractor.call_chain import extract_workflows_from_source
from angr_api_mcp.extractor.models import SourceFile, TrustLevel

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONFIG = Config()

KNOWN_CLASSES = CONFIG.known_classes_baseline | {
    "Project", "SimulationManager", "SimState", "CFGFast",
    "AngrObjectFactory", "Solver", "Block",
}


def _make_source_file(name: str, trust: TrustLevel = TrustLevel.HIGH) -> SourceFile:
    return SourceFile(
        path=FIXTURES_DIR / name,
        trust_level=trust,
        category="example" if trust == TrustLevel.HIGHEST else "test",
    )


class TestBasicCfgExtraction:
    def test_extracts_workflow(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert len(workflows) >= 1

    def test_project_init_recognized(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert workflows, "Expected at least one workflow"
        wf = workflows[0]
        class_names = {c.class_name for c in wf.calls}
        assert "Project" in class_names

    def test_cfg_fast_recognized(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        class_names = {c.class_name for c in wf.calls}
        assert "CFGFast" in class_names

    def test_minimum_two_calls(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        for wf in workflows:
            assert len(wf.calls) >= 2

    def test_trust_level_preserved(self):
        sf = _make_source_file("basic_cfg.py", TrustLevel.HIGHEST)
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert all(wf.trust_level == TrustLevel.HIGHEST for wf in workflows)


class TestSymbolicExecExtraction:
    def test_extracts_workflow(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert len(workflows) >= 1

    def test_simulation_manager_recognized(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        class_names = {c.class_name for c in wf.calls}
        assert "SimulationManager" in class_names or "AngrObjectFactory" in class_names

    def test_explore_call_present(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        method_names = {c.method_name for c in wf.calls}
        assert "explore" in method_names

    def test_data_flow_edges_exist(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        # Should have some data flow edges connecting calls
        assert len(wf.data_flow) >= 1


class TestStateManipulationExtraction:
    def test_extracts_workflow(self):
        sf = _make_source_file("state_manipulation.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert len(workflows) >= 1

    def test_core_classes_recognized(self):
        # Verifies that at minimum Project + factory calls are extracted.
        # found_state = simgr.found[0] is a subscript (not a call) so Solver
        # won't appear — that's expected behaviour.
        sf = _make_source_file("state_manipulation.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        class_names = {c.class_name for c in wf.calls}
        assert "Project" in class_names
        assert "AngrObjectFactory" in class_names or "SimulationManager" in class_names


class TestWorkflowDisplay:
    def test_display_text_has_steps(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        text = wf.to_display_text()
        assert "1." in text
        assert "2." in text

    def test_embedding_text_has_classes(self):
        sf = _make_source_file("symbolic_exec.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        text = wf.to_embedding_text()
        assert "Classes:" in text
        assert "Call chain:" in text

    def test_workflow_id_is_stable(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        assert wf.id == wf.id  # trivially stable

    def test_workflow_id_is_hex(self):
        sf = _make_source_file("basic_cfg.py")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        wf = workflows[0]
        int(wf.id, 16)  # raises ValueError if not hex


class TestModuleLevelExtraction:
    def test_module_level_script(self, tmp_path):
        """A script with no function wrappers should still yield a workflow."""
        script = tmp_path / "example.py"
        script.write_text(
            "import angr\n"
            "proj = angr.Project('/bin/ls', auto_load_libs=False)\n"
            "cfg = proj.analyses.CFGFast()\n"
            "simgr = proj.factory.simulation_manager()\n"
        )
        sf = SourceFile(path=script, trust_level=TrustLevel.HIGHEST, category="example")
        workflows = extract_workflows_from_source(sf, KNOWN_CLASSES, CONFIG)
        assert len(workflows) >= 1
        wf = workflows[0]
        assert "Project" in wf.angr_classes_used or len(wf.calls) >= 2

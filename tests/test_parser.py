"""Tests for the Python tree-sitter parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from angr_api_mcp.parser.python_parser import (
    find_class_names,
    find_function_bodies,
    find_imports,
    find_module_level_statements,
    parse_python,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _read(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


class TestImportExtraction:
    def test_simple_import(self):
        source = b"import angr\n"
        tree = parse_python(source)
        imports = find_imports(tree, source)
        assert "angr" in imports
        assert imports["angr"] == "angr"

    def test_dotted_import(self):
        source = b"import angr.analyses\n"
        tree = parse_python(source)
        imports = find_imports(tree, source)
        # First component is the local name
        assert "angr" in imports

    def test_from_import(self):
        source = b"from angr import Project\n"
        tree = parse_python(source)
        imports = find_imports(tree, source)
        assert "Project" in imports
        assert imports["Project"] == "angr.Project"

    def test_from_submodule_import(self):
        source = b"from angr.analyses import CFGFast\n"
        tree = parse_python(source)
        imports = find_imports(tree, source)
        assert "CFGFast" in imports
        assert "angr.analyses" in imports["CFGFast"]

    def test_aliased_import(self):
        source = b"from angr import Project as P\n"
        tree = parse_python(source)
        imports = find_imports(tree, source)
        assert "P" in imports
        assert "angr" in imports["P"]

    def test_fixture_has_angr_import(self):
        source = _read("basic_cfg.py")
        tree = parse_python(source)
        imports = find_imports(tree, source)
        assert "angr" in imports


class TestFunctionBodies:
    def test_finds_function(self):
        source = _read("basic_cfg.py")
        tree = parse_python(source)
        bodies = find_function_bodies(tree, source)
        assert len(bodies) >= 1
        names = [name for name, _ in bodies]
        assert "analyze_cfg" in names

    def test_finds_all_fixtures(self):
        for fixture in ("symbolic_exec.py", "state_manipulation.py"):
            source = _read(fixture)
            tree = parse_python(source)
            bodies = find_function_bodies(tree, source)
            assert len(bodies) >= 1


class TestClassNames:
    def test_no_classes_in_fixtures(self):
        source = _read("basic_cfg.py")
        tree = parse_python(source)
        names = find_class_names(tree, source)
        # Fixture files define no classes
        assert len(names) == 0

    def test_class_in_source(self):
        source = b"""
class MyAnalysis:
    pass

class AnotherClass(object):
    def method(self): pass
"""
        tree = parse_python(source)
        names = find_class_names(tree, source)
        assert "MyAnalysis" in names
        assert "AnotherClass" in names


class TestModuleLevelStatements:
    def test_module_level_in_script(self):
        source = b"""import angr
proj = angr.Project('/bin/ls', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
"""
        tree = parse_python(source)
        stmts = find_module_level_statements(tree)
        # In tree-sitter Python 0.21.x, `x = y` at module level is
        # expression_statement(assignment(...)), so check for that wrapper.
        assert len(stmts) >= 2
        types = {s.type for s in stmts}
        assert "expression_statement" in types or "assignment" in types

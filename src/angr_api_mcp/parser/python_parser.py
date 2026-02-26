"""Tree-sitter based Python parser for extracting AST information."""

from __future__ import annotations

from tree_sitter import Node, Tree
from tree_sitter_languages import get_language, get_parser

PYTHON_LANGUAGE = get_language("python")

# Pre-compiled queries for common AST patterns.
# NOTE: tree-sitter==0.21.3 is required. The captures() API changed in 0.23+
# and returns a dict instead of a list of (node, name) tuples.

# Matches: import angr  /  import angr.analyses
IMPORT_QUERY = PYTHON_LANGUAGE.query("""
(import_statement
  name: (dotted_name) @import_path)
""")

# Matches: from angr import Project  /  from angr.analyses import CFGFast
IMPORT_FROM_QUERY = PYTHON_LANGUAGE.query("""
(import_from_statement
  module_name: (dotted_name) @module
  name: (dotted_name) @name)
""")

# Matches aliased imports: from angr import Project as P
IMPORT_FROM_ALIAS_QUERY = PYTHON_LANGUAGE.query("""
(import_from_statement
  module_name: (dotted_name) @module
  name: (aliased_import
    name: (dotted_name) @name
    alias: (identifier) @alias))
""")

# Function definitions (both top-level and method bodies)
FUNCTION_DEF_QUERY = PYTHON_LANGUAGE.query("""
(function_definition
  name: (identifier) @func_name
  body: (block) @body)
""")

# Class definitions — for building the known-class set
CLASS_DEF_QUERY = PYTHON_LANGUAGE.query("""
(class_definition
  name: (identifier) @class_name)
""")


def parse_python(source: bytes) -> Tree:
    """Parse Python source code into a tree-sitter AST."""
    parser = get_parser("python")
    return parser.parse(source)


def get_node_text(node: Node, source: bytes) -> str:
    """Extract the text of an AST node from the source."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def find_imports(tree: Tree, source: bytes) -> dict[str, str]:
    """Extract import statements, returning a map of local_name -> module_path.

    Examples:
        import angr                           -> {"angr": "angr"}
        import angr.analyses                  -> {"angr.analyses": "angr.analyses"}
        from angr import Project              -> {"Project": "angr.Project"}
        from angr.analyses import CFGFast     -> {"CFGFast": "angr.analyses.CFGFast"}
        from angr import Project as P         -> {"P": "angr.Project"}
    """
    imports: dict[str, str] = {}

    # import X  /  import X.Y
    for node, _name in IMPORT_QUERY.captures(tree.root_node):
        path = get_node_text(node, source)
        # The local name is the first dotted component
        local = path.split(".")[0]
        imports[local] = path

    # from X import Y  (no alias)
    captures = IMPORT_FROM_QUERY.captures(tree.root_node)
    modules = [(n, nm) for n, nm in captures if nm == "module"]
    names = [(n, nm) for n, nm in captures if nm == "name"]
    for (mod_node, _), (name_node, _) in zip(modules, names):
        module = get_node_text(mod_node, source)
        name = get_node_text(name_node, source)
        local = name.split(".")[-1]
        imports[local] = f"{module}.{name}"

    # from X import Y as Z  (aliased)
    alias_captures = IMPORT_FROM_ALIAS_QUERY.captures(tree.root_node)
    alias_modules = [(n, nm) for n, nm in alias_captures if nm == "module"]
    alias_names = [(n, nm) for n, nm in alias_captures if nm == "name"]
    alias_aliases = [(n, nm) for n, nm in alias_captures if nm == "alias"]
    for (mod_node, _), (name_node, _), (alias_node, _) in zip(
        alias_modules, alias_names, alias_aliases
    ):
        module = get_node_text(mod_node, source)
        name = get_node_text(name_node, source)
        alias = get_node_text(alias_node, source)
        imports[alias] = f"{module}.{name}"

    return imports


def find_function_bodies(tree: Tree, source: bytes) -> list[tuple[str, Node]]:
    """Find all function definitions, returning (func_name, body_node) pairs.

    Includes top-level functions and methods inside class bodies.
    """
    results: list[tuple[str, Node]] = []
    captures = FUNCTION_DEF_QUERY.captures(tree.root_node)

    names = [(n, nm) for n, nm in captures if nm == "func_name"]
    bodies = [(n, nm) for n, nm in captures if nm == "body"]

    for (name_node, _), (body_node, _) in zip(names, bodies):
        func_name = get_node_text(name_node, source)
        results.append((func_name, body_node))

    return results


def find_class_names(tree: Tree, source: bytes) -> set[str]:
    """Extract all class names defined in this file."""
    names: set[str] = set()
    for node, _capture in CLASS_DEF_QUERY.captures(tree.root_node):
        names.add(get_node_text(node, source))
    return names


def find_module_level_statements(tree: Tree) -> list[Node]:
    """Return top-level statement nodes from the module root.

    Used to extract workflows from angr-doc example scripts that have no
    function wrappers — just top-level assignment and expression statements.
    """
    statements = []
    for child in tree.root_node.named_children:
        if child.type in (
            "assignment",
            "expression_statement",
            "augmented_assignment",
        ):
            statements.append(child)
    return statements

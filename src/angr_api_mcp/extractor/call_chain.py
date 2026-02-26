"""Extract angr API call chains from parsed Python ASTs."""

from __future__ import annotations

import logging
import re

from tree_sitter import Node

from angr_api_mcp.config import Config
from angr_api_mcp.extractor.models import (
    ApiCall,
    DataFlowEdge,
    SourceFile,
    Workflow,
)
from angr_api_mcp.parser.python_parser import (
    find_function_bodies,
    find_imports,
    find_module_level_statements,
    get_node_text,
    parse_python,
)

logger = logging.getLogger(__name__)


def _walk_nodes_by_offset(node: Node) -> list[Node]:
    """Recursively collect all descendant nodes, sorted by byte offset."""
    nodes: list[Node] = []
    cursor = node.walk()

    def _visit() -> None:
        nodes.append(cursor.node)
        if cursor.goto_first_child():
            _visit()
            while cursor.goto_next_sibling():
                _visit()
            cursor.goto_parent()

    _visit()
    nodes.sort(key=lambda n: n.start_byte)
    return nodes


def _extract_argument_identifiers(args_node: Node, source: bytes) -> list[str]:
    """Extract identifier names from an argument_list node.

    Handles positional args and keyword args (captures the value identifier).
    """
    identifiers: list[str] = []
    if args_node is None:
        return identifiers
    for child in args_node.named_children:
        if child.type == "identifier":
            identifiers.append(get_node_text(child, source))
        elif child.type == "keyword_argument":
            value = child.child_by_field_name("value")
            if value and value.type == "identifier":
                identifiers.append(get_node_text(value, source))
        elif child.type == "attribute":
            # e.g., TaskMonitor.DUMMY — capture full text for display
            identifiers.append(get_node_text(child, source))
    return identifiers


def _generate_description(
    function_name: str, classes_used: set[str], source_snippet: str
) -> str:
    """Auto-generate a workflow description from available context."""
    # Try to extract a Python docstring
    doc_match = re.search(r'"""(.*?)"""', source_snippet, re.DOTALL)
    if not doc_match:
        doc_match = re.search(r"'''(.*?)'''", source_snippet, re.DOTALL)
    if doc_match:
        doc = doc_match.group(1).strip()
        if doc:
            return doc[:500]

    # Fall back: snake_case → words + class list
    words = function_name.replace("_", " ")
    class_list = ", ".join(sorted(classes_used))
    return f"{words} using {class_list}"


def _resolve_attribute_chain(
    function_node: Node,
    source: bytes,
    var_tracker: dict[str, tuple[str, int]],
    angr_import_map: dict[str, str],
    known_classes: set[str],
    config: Config,
) -> tuple[str, str, str | None] | None:
    """Resolve attribute-chain function nodes to (class_name, method_name, receiver_var).

    Handles three depths:
      1. obj.method(...)          — tracked var or known import
      2. obj.attr.method(...)     — two-level property chain
      3. module.ClassName(...)    — direct constructor from module

    Returns (class_name, method_name, receiver_var) or None if not angr-related.
    """
    attr_node = function_node.child_by_field_name("attribute")
    obj_node = function_node.child_by_field_name("object")
    if attr_node is None or obj_node is None:
        return None

    method_name = get_node_text(attr_node, source)
    obj_text = get_node_text(obj_node, source)

    # Case 1: Direct call on a tracked class instance: simgr.explore(...)
    if obj_text in var_tracker:
        class_name = var_tracker[obj_text][0]
        # "angr_module" means it's a module reference (import angr), not a class
        # instance — fall through to Case 2 to handle angr.ClassName(...) correctly.
        if class_name != "angr_module":
            return (class_name, method_name, obj_text)

    # Case 2: Call on an angr module name: angr.Project(...)
    if obj_text in angr_import_map:
        if method_name in known_classes:
            return (method_name, "__init__", None)
        # Bare angr.something that isn't a known class — skip
        return None

    # Case 3: Two-level attribute chain: obj.factory.method() or obj.analyses.CFGFast()
    if obj_node.type == "attribute":
        inner_attr = obj_node.child_by_field_name("attribute")
        inner_obj = obj_node.child_by_field_name("object")
        if inner_attr is None or inner_obj is None:
            return None

        inner_attr_name = get_node_text(inner_attr, source)
        inner_obj_text = get_node_text(inner_obj, source)

        if inner_obj_text in var_tracker:
            tracked_class = var_tracker[inner_obj_text][0]

            # Check if the final attribute is a known class constructor:
            # e.g., proj.analyses.CFGFast()
            if method_name in known_classes:
                return (method_name, "__init__", inner_obj_text)

            # Lookup via property table: (tracked_class, inner_attr) → intermediate type
            key = f"{tracked_class}.{inner_attr_name}"
            intermediate = config.angr_property_return_types.get(key)
            if intermediate:
                return (intermediate, method_name, inner_obj_text)

        # Also handle: angr.module.ClassName() — e.g., angr.analyses.CFGFast()
        if inner_obj_text in angr_import_map:
            if method_name in known_classes:
                return (method_name, "__init__", None)

    return None


def _process_call_node(
    call_node: Node,
    source: bytes,
    var_tracker: dict[str, tuple[str, int]],
    angr_import_map: dict[str, str],
    known_classes: set[str],
    config: Config,
) -> ApiCall | None:
    """Try to extract an angr ApiCall from a `call` AST node."""
    function_node = call_node.child_by_field_name("function")
    args_node = call_node.child_by_field_name("arguments")

    if function_node is None:
        return None

    arg_vars = _extract_argument_identifiers(args_node, source) if args_node else []

    # Bare identifier call: Project(...) when imported directly
    if function_node.type == "identifier":
        func_name = get_node_text(function_node, source)
        if func_name in known_classes and func_name in angr_import_map:
            return ApiCall(
                class_name=func_name,
                method_name="__init__",
                full_text=get_node_text(call_node, source),
                line_number=call_node.start_point[0] + 1,
                byte_offset=call_node.start_byte,
                receiver_var=None,
                argument_vars=arg_vars,
            )
        return None

    # Attribute call: obj.method(...)  /  obj.attr.method(...)
    if function_node.type == "attribute":
        resolved = _resolve_attribute_chain(
            function_node, source, var_tracker,
            angr_import_map, known_classes, config,
        )
        if resolved is None:
            return None
        class_name, method_name, receiver_var = resolved
        return ApiCall(
            class_name=class_name,
            method_name=method_name,
            full_text=get_node_text(call_node, source),
            line_number=call_node.start_point[0] + 1,
            byte_offset=call_node.start_byte,
            receiver_var=receiver_var,
            argument_vars=arg_vars,
        )

    return None


def _track_variable_assignment(
    call_node: Node,
    source: bytes,
    call: ApiCall,
    call_index: int,
    var_tracker: dict[str, tuple[str, int]],
    config: Config,
) -> None:
    """Check if this call's result is assigned to a variable and track it."""
    parent = call_node.parent
    if parent is None:
        return

    if parent.type == "assignment":
        # Ensure the call_node IS the right-hand side (not the left)
        right_node = parent.child_by_field_name("right")
        if right_node is None or right_node.start_byte != call_node.start_byte:
            return
        left_node = parent.child_by_field_name("left")
        if left_node is None or left_node.type != "identifier":
            return
        var_name = get_node_text(left_node, source)
        call.return_var = var_name

        # Infer return type from the property table:
        # e.g., AngrObjectFactory.entry_state -> SimState
        tracked_class = call.class_name
        lookup_key = f"{call.class_name}.{call.method_name}"
        inferred = config.angr_property_return_types.get(lookup_key)
        if inferred:
            tracked_class = inferred

        var_tracker[var_name] = (tracked_class, call_index)


def _build_data_flow_edges(
    call: ApiCall,
    call_index: int,
    var_tracker: dict[str, tuple[str, int]],
    data_flow: list[DataFlowEdge],
) -> None:
    """Build data flow edges from tracked variables into this call."""
    if call.receiver_var and call.receiver_var in var_tracker:
        _src_class, source_idx = var_tracker[call.receiver_var]
        if source_idx != call_index and source_idx >= 0:
            data_flow.append(DataFlowEdge(
                source_call_index=source_idx,
                target_call_index=call_index,
                variable_name=call.receiver_var,
                role="receiver",
            ))

    for arg_var in call.argument_vars:
        if arg_var in var_tracker:
            _src_class, source_idx = var_tracker[arg_var]
            if source_idx != call_index and source_idx >= 0:
                data_flow.append(DataFlowEdge(
                    source_call_index=source_idx,
                    target_call_index=call_index,
                    variable_name=arg_var,
                    role="argument",
                ))


def _extract_workflow_from_nodes(
    nodes_to_walk: list[Node],
    body_node: Node | None,
    source: bytes,
    function_name: str,
    angr_import_map: dict[str, str],
    known_classes: set[str],
    var_tracker: dict[str, tuple[str, int]],
    config: Config,
    source_file: SourceFile,
) -> Workflow | None:
    """Core extraction logic: walk nodes, collect API calls and data-flow."""
    calls: list[ApiCall] = []
    data_flow: list[DataFlowEdge] = []
    angr_classes: set[str] = set()

    all_nodes = _walk_nodes_by_offset(
        body_node if body_node is not None else nodes_to_walk[0].parent or nodes_to_walk[0]
    ) if body_node is not None else nodes_to_walk

    for node in all_nodes:
        if node.type != "call":
            continue

        api_call = _process_call_node(
            node, source, var_tracker, angr_import_map, known_classes, config
        )
        if api_call is None:
            continue

        call_index = len(calls)
        calls.append(api_call)
        angr_classes.add(api_call.class_name)

        _track_variable_assignment(
            node, source, api_call, call_index, var_tracker, config
        )
        _build_data_flow_edges(api_call, call_index, var_tracker, data_flow)

    if not calls:
        return None

    if body_node is not None:
        parent = body_node.parent
        snippet_start = parent.start_byte if parent else body_node.start_byte
        snippet_end = body_node.end_byte
    else:
        # Module-level: span all walked nodes
        snippet_start = all_nodes[0].start_byte if all_nodes else 0
        snippet_end = all_nodes[-1].end_byte if all_nodes else 0

    source_snippet = source[snippet_start:snippet_end].decode("utf-8", errors="replace")
    description = _generate_description(function_name, angr_classes, source_snippet)

    return Workflow(
        calls=calls,
        data_flow=data_flow,
        source_snippet=source_snippet,
        function_name=function_name,
        file_path=str(source_file.path),
        trust_level=source_file.trust_level,
        category=source_file.category,
        angr_classes_used=angr_classes,
        description=description,
    )


def _seed_var_tracker_from_params(
    body_node: Node,
    source: bytes,
    angr_import_map: dict[str, str],
    known_classes: set[str],
) -> dict[str, tuple[str, int]]:
    """Seed the variable tracker with typed function parameters."""
    var_tracker: dict[str, tuple[str, int]] = {}
    method_node = body_node.parent
    if method_node is None:
        return var_tracker

    params_node = method_node.child_by_field_name("parameters")
    if params_node is None:
        return var_tracker

    for param in params_node.named_children:
        # typed_parameter: name: type
        if param.type == "typed_parameter":
            name_node = None
            type_node = None
            for child in param.named_children:
                if child.type == "identifier" and name_node is None:
                    name_node = child
                elif child.type in ("type", "identifier") and name_node is not None:
                    type_node = child
            if name_node and type_node:
                param_name = get_node_text(name_node, source)
                type_name = get_node_text(type_node, source)
                # Strip module prefix: angr.Project -> Project
                type_simple = type_name.rsplit(".", 1)[-1]
                if type_simple in known_classes:
                    var_tracker[param_name] = (type_simple, -1)
        # identifier parameter (no annotation) — skip; can't infer type
    return var_tracker


def extract_workflows_from_source(
    source_file: SourceFile,
    known_classes: set[str],
    config: Config,
) -> list[Workflow]:
    """Extract all angr API workflows from a single Python source file.

    Args:
        source_file: The Python file to process.
        known_classes: Set of known angr class names (simple names).
        config: Application configuration.

    Returns:
        List of Workflow objects with ≥2 API calls each.
    """
    try:
        source = source_file.path.read_bytes()
    except (OSError, IOError) as e:
        logger.warning("Could not read %s: %s", source_file.path, e)
        return []

    tree = parse_python(source)
    imports = find_imports(tree, source)

    # Build the map of local names that refer to the angr package/submodules
    angr_import_map: dict[str, str] = {
        local: fqn for local, fqn in imports.items()
        if fqn.startswith("angr") or local == "angr"
    }

    if not angr_import_map:
        # No angr imports; nothing to extract
        return []

    # Add the angr module itself if imported
    if "angr" in imports:
        angr_import_map["angr"] = "angr"

    workflows: list[Workflow] = []

    # 1. Extract from each function/method body
    for func_name, body_node in find_function_bodies(tree, source):
        var_tracker = _seed_var_tracker_from_params(
            body_node, source, angr_import_map, known_classes
        )
        # Always seed the angr module name itself so angr.Project(...) is recognized
        for local, fqn in angr_import_map.items():
            if local not in var_tracker:
                var_tracker[local] = ("angr_module", -1)

        wf = _extract_workflow_from_nodes(
            nodes_to_walk=[],
            body_node=body_node,
            source=source,
            function_name=func_name,
            angr_import_map=angr_import_map,
            known_classes=known_classes,
            var_tracker=var_tracker,
            config=config,
            source_file=source_file,
        )
        if wf and len(wf.calls) >= 2:
            workflows.append(wf)

    # 2. Module-level extraction for example scripts with no function wrappers
    module_stmts = find_module_level_statements(tree)
    if module_stmts and (not workflows or source_file.category == "example"):
        # Collect all call nodes from the module-level statements
        var_tracker: dict[str, tuple[str, int]] = {}
        for local in angr_import_map:
            var_tracker[local] = ("angr_module", -1)

        calls: list[ApiCall] = []
        data_flow: list[DataFlowEdge] = []
        angr_classes: set[str] = set()

        for stmt in module_stmts:
            for node in _walk_nodes_by_offset(stmt):
                if node.type != "call":
                    continue
                api_call = _process_call_node(
                    node, source, var_tracker, angr_import_map, known_classes, config
                )
                if api_call is None:
                    continue
                call_index = len(calls)
                calls.append(api_call)
                angr_classes.add(api_call.class_name)
                _track_variable_assignment(
                    node, source, api_call, call_index, var_tracker, config
                )
                _build_data_flow_edges(api_call, call_index, var_tracker, data_flow)

        if len(calls) >= 2:
            file_stem = source_file.path.stem
            snippet = source.decode("utf-8", errors="replace")
            description = _generate_description(file_stem, angr_classes, snippet)
            wf = Workflow(
                calls=calls,
                data_flow=data_flow,
                source_snippet=snippet[:2000],
                function_name="<module>",
                file_path=str(source_file.path),
                trust_level=source_file.trust_level,
                category=source_file.category,
                angr_classes_used=angr_classes,
                description=description,
            )
            workflows.append(wf)

    return workflows

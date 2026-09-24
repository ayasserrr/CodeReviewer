"""Tree-sitter based structural extraction for the DependencyGraph node.

Parses one Python file at a time and extracts every function/method,
class, lexical containment relationship, and call site — the raw material
``helpers.call_resolution.resolve_calls`` turns into ``CallEdge``s.

Call extraction is deliberately "flattened": every call anywhere inside a
function's body (through ``if``/``for``/``try``/``with``, comprehensions,
lambdas, and nested call arguments like ``foo(bar(), baz(qux()))``) is
captured, not just calls that are direct statements. The one boundary that
*is* respected is a nested ``def``/``class`` — those calls belong to the
inner scope and are attributed to it when that inner function is itself
processed, not to the outer function that lexically contains it.
"""

import hashlib
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from utils import ClassNode, ContainsEdge, FunctionNode

_DEF_TYPES = ("function_definition", "class_definition")

RawCall = dict[str, object]


def build_python_parser() -> Parser:
    """Builds a ``Parser`` configured for Python source."""
    return Parser(Language(tspython.language()))


def parse_file(parser: Parser, file_path: Path, repo_path: Path) -> tuple[str, bytes, Node]:
    """Parses one file, returning its repo-relative path, raw source, and root AST node."""
    source = file_path.read_bytes()
    tree = parser.parse(source)
    rel_path = file_path.resolve().relative_to(repo_path).as_posix()
    return rel_path, source, tree.root_node


def extract_file_elements(
    root_node: Node, source: bytes, rel_path: str
) -> tuple[list[FunctionNode], list[ClassNode], list[ContainsEdge], dict[str, list[RawCall]]]:
    """Extracts every function, class, containment edge, and raw call site from one parsed file.

    Returns:
        ``(functions, classes, contains_edges, raw_calls_by_function_id)`` —
        the last dict maps a ``FunctionNode.id`` to every call captured in
        its own body (see module docstring for the flattening/boundary rule).
    """
    functions: list[FunctionNode] = []
    classes: list[ClassNode] = []
    contains_edges: list[ContainsEdge] = []
    raw_calls_by_function: dict[str, list[RawCall]] = {}

    _walk_scope(
        root_node, source, rel_path,
        qualname_prefix="", parent_id=rel_path,
        functions=functions, classes=classes,
        contains_edges=contains_edges, raw_calls_by_function=raw_calls_by_function,
    )
    return functions, classes, contains_edges, raw_calls_by_function


def _walk_scope(
    node: Node, source: bytes, rel_path: str, qualname_prefix: str, parent_id: str,
    functions: list[FunctionNode], classes: list[ClassNode],
    contains_edges: list[ContainsEdge], raw_calls_by_function: dict[str, list[RawCall]],
) -> None:
    """Recursively finds every def/class anywhere in ``node``'s subtree.

    Unlike call-flattening, containment must see every nesting level (a
    function defined inside an ``if`` block at module scope is still a
    module-level function), so this recurses into every node type.
    """
    for child in node.children:
        def_node, decorators = _unwrap_decorated(child, source)

        if def_node is not None and def_node.type == "class_definition":
            _handle_class(
                def_node, decorators, source, rel_path, qualname_prefix, parent_id,
                functions, classes, contains_edges, raw_calls_by_function,
            )
        elif def_node is not None and def_node.type == "function_definition":
            fn_id, fn_qualname = _handle_function(
                def_node, decorators, source, rel_path, qualname_prefix, parent_id,
                functions, contains_edges, raw_calls_by_function,
            )
            body = def_node.child_by_field_name("body")
            if body is not None:
                _walk_scope(
                    body, source, rel_path, fn_qualname, fn_id,
                    functions, classes, contains_edges, raw_calls_by_function,
                )
        else:
            _walk_scope(
                child, source, rel_path, qualname_prefix, parent_id,
                functions, classes, contains_edges, raw_calls_by_function,
            )


def _handle_class(
    class_node: Node, decorators: tuple[str, ...], source: bytes, rel_path: str,
    qualname_prefix: str, parent_id: str,
    functions: list[FunctionNode], classes: list[ClassNode],
    contains_edges: list[ContainsEdge], raw_calls_by_function: dict[str, list[RawCall]],
) -> None:
    name = _node_text(class_node.child_by_field_name("name"), source)
    qualname = f"{qualname_prefix}.{name}" if qualname_prefix else name
    node_id = f"{rel_path}::{qualname}"
    body = class_node.child_by_field_name("body")

    classes.append(ClassNode(
        id=node_id, name=name, qualname=qualname, file=rel_path,
        start_line=class_node.start_point[0] + 1, end_line=class_node.end_point[0] + 1,
        start_byte=class_node.start_byte, end_byte=class_node.end_byte,
        method_count=_method_count(body), content_hash=_content_hash(class_node, source),
        loc=class_node.end_point[0] - class_node.start_point[0] + 1,
    ))
    contains_edges.append(ContainsEdge(parent_id=parent_id, child_id=node_id))

    if body is not None:
        _walk_scope(
            body, source, rel_path, qualname, node_id,
            functions, classes, contains_edges, raw_calls_by_function,
        )


def _handle_function(
    def_node: Node, decorators: tuple[str, ...], source: bytes, rel_path: str,
    qualname_prefix: str, parent_id: str,
    functions: list[FunctionNode], contains_edges: list[ContainsEdge],
    raw_calls_by_function: dict[str, list[RawCall]],
) -> tuple[str, str]:
    name = _node_text(def_node.child_by_field_name("name"), source)
    qualname = f"{qualname_prefix}.{name}" if qualname_prefix else name
    node_id = f"{rel_path}::{qualname}"
    is_async = bool(def_node.children) and def_node.children[0].type == "async"

    calls: list[RawCall] = []
    body = def_node.child_by_field_name("body")
    if body is not None:
        _walk_calls(body, source, calls)
    raw_calls_by_function[node_id] = calls

    functions.append(FunctionNode(
        id=node_id, name=name, qualname=qualname, file=rel_path,
        start_line=def_node.start_point[0] + 1, end_line=def_node.end_point[0] + 1,
        start_byte=def_node.start_byte, end_byte=def_node.end_byte,
        is_async=is_async, decorators=decorators, params=_params_of(def_node, source),
        content_hash=_content_hash(def_node, source),
        loc=def_node.end_point[0] - def_node.start_point[0] + 1,
    ))
    contains_edges.append(ContainsEdge(parent_id=parent_id, child_id=node_id))
    return node_id, qualname


def _walk_calls(node: Node, source: bytes, calls: list[RawCall]) -> None:
    for child in node.children:
        if child.type in _DEF_TYPES:
            continue  # belongs to the inner scope, handled when that def is processed
        if child.type == "call":
            name = _rightmost_name(child.child_by_field_name("function"), source)
            if name:
                calls.append({
                    "resolved_name": name,
                    "line": child.start_point[0] + 1,
                    "col": child.start_point[1],
                })
        _walk_calls(child, source, calls)


def _unwrap_decorated(node: Node, source: bytes) -> tuple[Node | None, tuple[str, ...]]:
    """Returns the underlying def/class node and its decorators (empty if undecorated)."""
    if node.type in _DEF_TYPES:
        return node, ()
    if node.type != "decorated_definition":
        return None, ()

    decorators: list[str] = []
    inner: Node | None = None
    for child in node.children:
        if child.type == "decorator":
            decorators.append(_node_text(child, source)[1:].strip())
        elif child.type in _DEF_TYPES:
            inner = child
    return inner, tuple(decorators)


def _method_count(class_body: Node | None) -> int:
    if class_body is None:
        return 0
    return sum(1 for child in class_body.children if _is_method_definition(child))


def _is_method_definition(node: Node) -> bool:
    if node.type == "function_definition":
        return True
    return node.type == "decorated_definition" and any(
        c.type == "function_definition" for c in node.children
    )


def _params_of(def_node: Node, source: bytes) -> tuple[str, ...]:
    params_node = def_node.child_by_field_name("parameters")
    if params_node is None:
        return ()
    names: list[str] = []
    for child in params_node.named_children:
        if child.type == "identifier":
            names.append(_node_text(child, source))
            continue
        name_node = child.child_by_field_name("name") or next(
            (c for c in child.named_children if c.type == "identifier"), None
        )
        if name_node is not None:
            names.append(_node_text(name_node, source))
    return tuple(names)


def _rightmost_name(expr: Node | None, source: bytes) -> str | None:
    if expr is None:
        return None
    if expr.type == "identifier":
        return _node_text(expr, source)
    if expr.type == "attribute":
        attr = expr.child_by_field_name("attribute")
        return _node_text(attr, source) if attr is not None else None
    return None


def _node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _content_hash(node: Node, source: bytes) -> str:
    return hashlib.sha256(source[node.start_byte:node.end_byte]).hexdigest()

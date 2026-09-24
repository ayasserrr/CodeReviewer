"""Resolves raw tree-sitter call sites into repo-local ``CallEdge``s.

A call's simple name is matched against every function in the repository
sharing that name: zero candidates means it's an external/library call
(nothing in this repo defines it), more than one means it's ambiguous
(e.g. two classes each defining a same-named method — without type
inference, which name it actually dispatches to at runtime can't be
determined from tree-sitter alone). Only a unique match becomes an edge.
"""

from collections import defaultdict
from typing import NamedTuple

from utils import CallEdge, FunctionNode


def build_name_table(functions: list[FunctionNode]) -> dict[str, list[str]]:
    """Maps a function's simple name to every function id sharing that name."""
    table: dict[str, list[str]] = defaultdict(list)
    for function in functions:
        table[function.name].append(function.id)
    return table


class CallResolutionResult(NamedTuple):
    """Flattened call edges plus the counts behind ``DependencyGraphStatistics``."""

    call_edges: list[CallEdge]
    calls_found: int
    calls_skipped_external: int
    calls_skipped_ambiguous: int


def resolve_calls(
    functions: list[FunctionNode], raw_calls_by_function: dict[str, list[dict]]
) -> CallResolutionResult:
    """Resolves every function's raw calls (see ``helpers.dependency_ast_extractor``)
    into ``CallEdge``s via the repo-wide name table.
    """
    name_table = build_name_table(functions)
    call_edges: list[CallEdge] = []
    calls_found = 0
    skipped_external = 0
    skipped_ambiguous = 0

    for caller_id, raw_calls in raw_calls_by_function.items():
        for raw_call in raw_calls:
            calls_found += 1
            candidates = name_table.get(raw_call["resolved_name"], [])
            if len(candidates) == 0:
                skipped_external += 1
            elif len(candidates) > 1:
                skipped_ambiguous += 1
            else:
                call_edges.append(CallEdge(
                    caller_id=caller_id, callee_id=candidates[0],
                    line=raw_call["line"], col=raw_call["col"],
                ))

    return CallResolutionResult(call_edges, calls_found, skipped_external, skipped_ambiguous)

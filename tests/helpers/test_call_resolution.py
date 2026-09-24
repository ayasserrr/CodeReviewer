from helpers.call_resolution import build_name_table, resolve_calls
from utils import FunctionNode


def _fn(id_: str, name: str) -> FunctionNode:
    return FunctionNode(
        id=id_, name=name, qualname=name, file="mod.py",
        start_line=1, end_line=2, start_byte=0, end_byte=10,
        content_hash="deadbeef", loc=2,
    )


class TestBuildNameTable:
    def test_groups_by_simple_name(self):
        functions = [_fn("mod.py::foo", "foo"), _fn("mod.py::Widget.foo", "foo"), _fn("mod.py::bar", "bar")]
        table = build_name_table(functions)
        assert sorted(table["foo"]) == ["mod.py::Widget.foo", "mod.py::foo"]
        assert table["bar"] == ["mod.py::bar"]


class TestResolveCalls:
    def test_unique_match_becomes_edge(self):
        functions = [_fn("mod.py::foo", "foo"), _fn("mod.py::bar", "bar")]
        raw_calls = {"mod.py::foo": [{"resolved_name": "bar", "line": 2, "col": 4}]}

        result = resolve_calls(functions, raw_calls)

        assert result.calls_found == 1
        assert result.calls_skipped_external == 0
        assert result.calls_skipped_ambiguous == 0
        assert len(result.call_edges) == 1
        edge = result.call_edges[0]
        assert edge.caller_id == "mod.py::foo"
        assert edge.callee_id == "mod.py::bar"
        assert edge.line == 2
        assert edge.col == 4

    def test_zero_candidates_skipped_as_external(self):
        functions = [_fn("mod.py::foo", "foo")]
        raw_calls = {"mod.py::foo": [{"resolved_name": "print", "line": 2, "col": 4}]}

        result = resolve_calls(functions, raw_calls)

        assert result.call_edges == []
        assert result.calls_skipped_external == 1
        assert result.calls_skipped_ambiguous == 0

    def test_multiple_candidates_skipped_as_ambiguous(self):
        functions = [
            _fn("mod.py::foo", "foo"),
            _fn("mod.py::A.helper", "helper"),
            _fn("mod.py::B.helper", "helper"),
        ]
        raw_calls = {"mod.py::foo": [{"resolved_name": "helper", "line": 2, "col": 4}]}

        result = resolve_calls(functions, raw_calls)

        assert result.call_edges == []
        assert result.calls_skipped_external == 0
        assert result.calls_skipped_ambiguous == 1

    def test_calls_found_counts_every_raw_call_regardless_of_outcome(self):
        functions = [_fn("mod.py::foo", "foo"), _fn("mod.py::bar", "bar")]
        raw_calls = {
            "mod.py::foo": [
                {"resolved_name": "bar", "line": 1, "col": 0},
                {"resolved_name": "print", "line": 2, "col": 0},
            ]
        }

        result = resolve_calls(functions, raw_calls)

        assert result.calls_found == 2
        assert len(result.call_edges) == 1
        assert result.calls_skipped_external == 1

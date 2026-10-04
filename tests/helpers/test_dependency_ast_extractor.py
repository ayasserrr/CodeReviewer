"""Unit tests for tree-sitter based structural extraction.

Parses real source snippets (no mocking tree-sitter itself) to verify
function/class extraction, qualname/id construction, and specifically the
flatten-calls behavior described in the module docstring.
"""

from pathlib import Path

from helpers.dependency_ast_extractor import (
    build_python_parser,
    extract_file_elements,
    parse_file,
)


def _extract(source: str, rel_path: str = "mod.py"):
    parser = build_python_parser()
    src_bytes = source.encode("utf-8")
    tree = parser.parse(src_bytes)
    return extract_file_elements(tree.root_node, src_bytes, rel_path)


class TestParseFile:
    def test_parse_file_returns_repo_relative_path(self, tmp_path: Path):
        (tmp_path / "pkg").mkdir()
        file_path = tmp_path / "pkg" / "mod.py"
        file_path.write_text("def f():\n    pass\n")

        parser = build_python_parser()
        rel_path, source, root_node = parse_file(parser, file_path, tmp_path)

        assert rel_path == "pkg/mod.py"
        assert source == file_path.read_bytes()
        assert root_node.type == "module"

    def test_utf8_bom_is_stripped_so_functions_start_at_line_1(self, tmp_path: Path):
        file_path = tmp_path / "bom.py"
        file_path.write_bytes(b"\xef\xbb\xbfdef f():\n    pass\n")

        parser = build_python_parser()
        rel_path, source, root_node = parse_file(parser, file_path, tmp_path)
        functions, *_ = extract_file_elements(root_node, source, rel_path)

        assert not source.startswith(b"\xef\xbb\xbf")
        assert [(fn.name, fn.start_line) for fn in functions] == [("f", 1)]


class TestFunctionExtraction:
    def test_top_level_function_fields(self):
        functions, _, _, _ = _extract("def foo(a, b=1, *args, **kwargs):\n    pass\n")
        assert len(functions) == 1
        fn = functions[0]
        assert fn.id == "mod.py::foo"
        assert fn.name == "foo"
        assert fn.qualname == "foo"
        assert fn.file == "mod.py"
        assert fn.is_async is False
        assert fn.params == ("a", "b", "args", "kwargs")

    def test_async_function_detected(self):
        functions, _, _, _ = _extract("async def foo():\n    pass\n")
        assert functions[0].is_async is True

    def test_decorators_captured_in_source_order(self):
        source = "@first\n@second(arg=1)\ndef foo():\n    pass\n"
        functions, _, _, _ = _extract(source)
        assert functions[0].decorators == ("first", "second(arg=1)")

    def test_typed_and_default_params_extracted_by_name(self):
        functions, _, _, _ = _extract('def foo(x: int, y: str = "a"):\n    pass\n')
        assert functions[0].params == ("x", "y")

    def test_content_hash_stable_for_identical_bodies(self):
        functions1, _, _, _ = _extract("def foo():\n    return 1\n")
        functions2, _, _, _ = _extract("def foo():\n    return 1\n")
        assert functions1[0].content_hash == functions2[0].content_hash

    def test_content_hash_differs_for_different_bodies(self):
        functions1, _, _, _ = _extract("def foo():\n    return 1\n")
        functions2, _, _, _ = _extract("def foo():\n    return 2\n")
        assert functions1[0].content_hash != functions2[0].content_hash


class TestClassExtraction:
    def test_class_fields_and_method_count(self):
        source = (
            "class Widget:\n    def __init__(self):\n        pass\n    @staticmethod\n    def helper():\n        pass\n"
        )
        _, classes, _, _ = _extract(source)
        assert len(classes) == 1
        cls = classes[0]
        assert cls.id == "mod.py::Widget"
        assert cls.name == "Widget"
        assert cls.method_count == 2

    def test_method_qualname_is_dotted(self):
        source = "class Widget:\n    def helper(self):\n        pass\n"
        functions, _, _, _ = _extract(source)
        assert functions[0].qualname == "Widget.helper"
        assert functions[0].id == "mod.py::Widget.helper"


class TestContainsEdges:
    def test_file_contains_top_level_def(self):
        _, _, contains, _ = _extract("def foo():\n    pass\n")
        assert ("mod.py", "mod.py::foo") in [(e.parent_id, e.child_id) for e in contains]

    def test_class_contains_method(self):
        source = "class Widget:\n    def helper(self):\n        pass\n"
        _, _, contains, _ = _extract(source)
        pairs = [(e.parent_id, e.child_id) for e in contains]
        assert ("mod.py", "mod.py::Widget") in pairs
        assert ("mod.py::Widget", "mod.py::Widget.helper") in pairs

    def test_outer_function_contains_nested_function(self):
        source = "def outer():\n    def inner():\n        pass\n"
        _, _, contains, _ = _extract(source)
        pairs = [(e.parent_id, e.child_id) for e in contains]
        assert ("mod.py::outer", "mod.py::outer.inner") in pairs


class TestFlattenCalls:
    def test_direct_call_captured(self):
        functions, _, _, raw_calls = _extract("def foo():\n    bar()\n")
        calls = raw_calls[functions[0].id]
        assert [c["resolved_name"] for c in calls] == ["bar"]

    def test_nested_call_arguments_all_captured(self):
        """foo(bar(), baz(qux())) must yield bar, baz, and qux -- not just the outermost call."""
        functions, _, _, raw_calls = _extract("def foo():\n    outer(bar(), baz(qux()))\n")
        calls = raw_calls[functions[0].id]
        names = {c["resolved_name"] for c in calls}
        assert names == {"outer", "bar", "baz", "qux"}

    def test_call_inside_if_for_try_all_captured(self):
        source = (
            "def foo(items):\n"
            "    if cond():\n"
            "        pass\n"
            "    for x in items:\n"
            "        loop_call(x)\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception:\n"
            "        handle()\n"
        )
        functions, _, _, raw_calls = _extract(source)
        names = {c["resolved_name"] for c in raw_calls[functions[0].id]}
        assert names == {"cond", "loop_call", "risky", "handle"}

    def test_call_inside_comprehension_and_lambda_captured(self):
        source = "def foo(items):\n    f = lambda: inner_call()\n    return [transform(i) for i in items]\n"
        functions, _, _, raw_calls = _extract(source)
        names = {c["resolved_name"] for c in raw_calls[functions[0].id]}
        assert names == {"inner_call", "transform"}

    def test_method_call_resolves_to_rightmost_attribute(self):
        functions, _, _, raw_calls = _extract("def foo(self):\n    self.helper()\n")
        calls = raw_calls[functions[0].id]
        assert calls[0]["resolved_name"] == "helper"

    def test_nested_function_calls_not_attributed_to_outer_scope(self):
        source = "def outer():\n    def inner():\n        bar()\n    baz()\n"
        functions, _, _, raw_calls = _extract(source)
        by_qualname = {f.qualname: f.id for f in functions}

        outer_calls = {c["resolved_name"] for c in raw_calls[by_qualname["outer"]]}
        inner_calls = {c["resolved_name"] for c in raw_calls[by_qualname["outer.inner"]]}

        assert outer_calls == {"baz"}
        assert inner_calls == {"bar"}

    def test_decorator_call_attributed_to_enclosing_scope_not_nested_def(self):
        """A decorator's own call runs in the *enclosing* scope, not inside the def it decorates."""
        source = "def outer():\n    @decorator_factory(1)\n    def inner():\n        pass\n"
        functions, _, _, raw_calls = _extract(source)
        by_qualname = {f.qualname: f.id for f in functions}

        outer_calls = {c["resolved_name"] for c in raw_calls[by_qualname["outer"]]}
        inner_calls = {c["resolved_name"] for c in raw_calls[by_qualname["outer.inner"]]}

        assert outer_calls == {"decorator_factory"}
        assert inner_calls == set()

    def test_call_line_and_col_recorded(self):
        functions, _, _, raw_calls = _extract("def foo():\n    bar()\n")
        call = raw_calls[functions[0].id][0]
        assert call["line"] == 2
        assert call["col"] == 4

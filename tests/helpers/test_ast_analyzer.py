import time
from pathlib import Path
from unittest.mock import patch

from helpers.ast_analyzer import parse_file_ast


class TestParseFileAst:
    def test_valid_file_returns_tree_with_size_and_lines(self, tmp_path: Path):
        f = tmp_path / "valid.py"
        f.write_text("def add(a, b):\n    return a + b\n")
        outcome = parse_file_ast(f, max_size_mb=2.0, timeout_ms=50)
        assert outcome.tree is not None
        assert outcome.parse_error is False
        assert outcome.size_bytes == f.stat().st_size
        assert outcome.lines == 2

    def test_syntax_error_sets_parse_error(self, tmp_path: Path):
        f = tmp_path / "broken.py"
        f.write_text("def broken(:\n    pass\n")
        outcome = parse_file_ast(f, max_size_mb=2.0, timeout_ms=50)
        assert outcome.tree is None
        assert outcome.parse_error is True
        assert outcome.parse_error_message is not None

    def test_oversized_file_skipped_not_parsed(self, tmp_path: Path):
        f = tmp_path / "big.py"
        f.write_text("x = 1\n" * 1000)
        outcome = parse_file_ast(f, max_size_mb=0.0001, timeout_ms=50)
        assert outcome.tree is None
        assert outcome.skipped_due_to_size is True
        assert outcome.parse_error is False

    def test_missing_file_sets_parse_error(self, tmp_path: Path):
        outcome = parse_file_ast(tmp_path / "does-not-exist.py", max_size_mb=2.0, timeout_ms=50)
        assert outcome.parse_error is True
        assert outcome.tree is None

    def test_slow_parse_is_bounded_by_timeout(self, tmp_path: Path):
        """The caller must be unblocked at the timeout, not whenever the real parse finishes."""
        f = tmp_path / "slow.py"
        f.write_text("x = 1\n")

        def slow_parse(source, filename=""):
            import ast

            time.sleep(0.3)
            return ast.parse(source, filename=filename)

        with patch("ast.parse", side_effect=slow_parse):
            start = time.monotonic()
            outcome = parse_file_ast(f, max_size_mb=2.0, timeout_ms=50)
            elapsed = time.monotonic() - start

        assert outcome.ast_timeout is True
        assert outcome.tree is None
        assert elapsed < 0.2  # well under the real 0.3s parse time

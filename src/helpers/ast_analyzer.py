"""Per-file Python AST parsing under strict size and time caps.

Discovery is read-only and never executes code — ``ast.parse`` only builds a
syntax tree, it doesn't run anything. Scoped to ``.py`` files: this project's
own AST module is Python-specific, and going further (tree-sitter or similar
for other languages) is out of scope for this pass — non-Python files are
still classified and sized, just never AST-parsed.
"""

import ast
import re
import warnings
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from pathlib import Path

from system import get_logger

logger = get_logger(__name__)

# One small shared pool for the process lifetime — spinning up a fresh
# ThreadPoolExecutor per file would dwarf the 50ms budget itself.
_AST_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ast-parse")


@dataclass
class ParseOutcome:
    """Result of attempting to AST-parse one Python file.

    Exactly one of ``tree`` being non-``None``, ``parse_error``,
    ``skipped_due_to_size``, or ``ast_timeout`` describes what happened.
    """

    tree: ast.Module | None = None
    size_bytes: int = 0
    lines: int | None = None
    parse_error: bool = False
    parse_error_message: str | None = None
    skipped_due_to_size: bool = False
    ast_timeout: bool = False


# PEP 758 (Python 3.14): ``except A, B:`` without parentheses.
_UNPARENTHESIZED_EXCEPT = re.compile(r"(?m)^(\s*except\*?\s+)(?!\()([^\n:()#]+,[^\n:#]+?)\s*:")
_MAX_LINE_REPAIRS = 25


def parse_quietly(source: str, filename: str = "<unknown>") -> ast.Module:
    """``ast.parse`` without the reviewed code's own ``SyntaxWarning``s (e.g. invalid
    escape sequences) — they are the target repository's lint, not our logs' business.

    Syntax that is valid on a newer Python than this interpreter (PEP 758 ``except A, B:``)
    is accepted: it is rewritten to its equivalent before parsing, not reported as an error."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            return ast.parse(source, filename=filename)
        except SyntaxError:
            rewritten = _UNPARENTHESIZED_EXCEPT.sub(lambda m: f"{m.group(1)}({m.group(2).strip()}):", source)
            if rewritten == source:
                raise
            return ast.parse(rewritten, filename=filename)


def parse_tolerant(source: str, filename: str = "<unknown>") -> ast.Module:
    """Like :func:`parse_quietly`, but a line that still does not parse is neutralised in place
    (line numbers preserved, block headers keep their block) so the rest of the module is still
    analysed — for review analysis, where losing a whole module costs more than one line.
    Raises ``SyntaxError`` only when the file cannot be repaired."""
    try:
        return parse_quietly(source, filename)
    except SyntaxError:
        pass
    repaired = _UNPARENTHESIZED_EXCEPT.sub(lambda m: f"{m.group(1)}({m.group(2).strip()}):", source)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        for _ in range(_MAX_LINE_REPAIRS):
            try:
                return ast.parse(repaired, filename=filename)
            except SyntaxError as error:
                lines = repaired.split("\n")
                index = (error.lineno or 0) - 1
                if not 0 <= index < len(lines) or lines[index].strip() in ("pass", "if True:"):
                    raise
                indent = re.match(r"\s*", lines[index]).group(0)
                lines[index] = indent + ("if True:" if lines[index].rstrip().endswith(":") else "pass")
                repaired = "\n".join(lines)
        return ast.parse(repaired, filename=filename)


def parse_file_ast(path: Path, max_size_mb: float, timeout_ms: int) -> ParseOutcome:
    """AST-parse one Python file, enforcing the size cap and per-file timeout.

    The timeout is enforced by running the parse in a worker thread and
    bounding how long we wait for it (``concurrent.futures`` timeouts are
    cross-platform, unlike ``signal.alarm`` which doesn't exist on Windows).
    A file that blows the timeout is abandoned from the caller's perspective
    — the parse thread finishes in the background and is discarded — but the
    file itself is marked ``ast_timeout`` and treated as unparsed.

    Args:
        path: Absolute path to the ``.py`` file.
        max_size_mb: Size cap above which parsing is skipped entirely.
        timeout_ms: Max time to wait for the parse to complete.

    Returns:
        A ``ParseOutcome`` describing what happened — never raises for
        ordinary failures (syntax errors, timeouts, oversized files);
        those are all represented as flags on the result.
    """
    try:
        size_bytes = path.stat().st_size
    except OSError as exc:
        return ParseOutcome(parse_error=True, parse_error_message=str(exc))

    max_size_bytes = int(max_size_mb * 1024 * 1024)
    if size_bytes > max_size_bytes:
        logger.warning("discovery_file_skipped_size", path=str(path), size_bytes=size_bytes)
        return ParseOutcome(size_bytes=size_bytes, skipped_due_to_size=True)

    try:
        source = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return ParseOutcome(size_bytes=size_bytes, parse_error=True, parse_error_message=str(exc))

    if not source:
        lines = 0
    elif source.endswith("\n"):
        lines = source.count("\n")  # properly-terminated file: newline count == line count
    else:
        lines = source.count("\n") + 1  # last line has no trailing newline but still counts

    future = _AST_EXECUTOR.submit(parse_quietly, source, str(path))
    try:
        tree = future.result(timeout=timeout_ms / 1000)
    except FutureTimeoutError:
        logger.warning("discovery_ast_timeout", path=str(path), timeout_ms=timeout_ms)
        return ParseOutcome(size_bytes=size_bytes, lines=lines, ast_timeout=True)
    except SyntaxError as exc:
        return ParseOutcome(size_bytes=size_bytes, lines=lines, parse_error=True, parse_error_message=str(exc))
    except Exception as exc:  # defensive: any other parser failure shouldn't abort the whole scan
        return ParseOutcome(size_bytes=size_bytes, lines=lines, parse_error=True, parse_error_message=str(exc))

    return ParseOutcome(tree=tree, size_bytes=size_bytes, lines=lines)

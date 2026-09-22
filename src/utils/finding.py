"""The typed, content-hashed output of Static Analysis + Security Engine.

A ``@dataclass`` rather than the ``pydantic.BaseModel`` used elsewhere in
this package — a deliberate exception, matching what this finding type is
for: a lightweight, hashable value object built fresh from already-validated
normalized dicts, not something deserialized from external/untrusted input
(that validation already happened per-tool in the normalizer functions).
"""

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class StaticFinding:
    """One normalized finding from a static-analysis or security tool.

    Attributes:
        id: ``sha256(f"{tool}|{category}|{file}|{line}|{message}")[:16]`` —
            identical across repeat runs for an identical finding, so it
            doubles as a dedup/cache key for downstream KB/report stages.
        tool: Which tool produced this finding (e.g. ``"ruff"``, ``"bandit"``).
        file: Path relative to the repository root.
        line: 1-based line number, or ``None`` when the tool reports no
            specific line (e.g. a dependency-level pip-audit finding).
        severity: Tool-normalized severity (e.g. ``"warning"``, ``"error"``,
            ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, ``"info"``).
        category: Tool-specific rule/check identifier (e.g. a ruff code, a
            bandit test ID, or a fixed label like ``"dead_code"``).
        message: Human-readable description of the finding.
    """

    id: str
    tool: str
    file: str
    line: int | None
    severity: str
    category: str
    message: str

    @classmethod
    def from_normalized(cls, tool: str, data: dict) -> "StaticFinding":
        """Build a ``StaticFinding`` from one normalizer's output dict.

        Args:
            tool: Tool name, stored on the finding and folded into its id.
            data: A normalized finding dict with ``file``, ``line``,
                ``severity``, ``category``, ``message`` keys (see
                ``helpers.finding_normalizers``).
        """
        raw_key = f"{tool}|{data['category']}|{data['file']}|{data['line']}|{data['message']}"
        finding_id = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        return cls(
            id=finding_id,
            tool=tool,
            file=data["file"],
            line=data["line"],
            severity=data["severity"],
            category=data["category"],
            message=data["message"],
        )

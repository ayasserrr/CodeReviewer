"""Deterministic, evidence-based framework detection.

Scores each known framework from three independent signals:

- Evidence A — the package is listed as a dependency (``pyproject.toml`` / ``requirements.txt``).
- Evidence B — an explicit ``import`` of the framework's top-level module.
- Evidence C — an AST-level usage pattern (app instantiation, route decorator,
  class-based view base, ...).

Weighted A=1, B=1, C=2, so: A alone -> score 1 (LOW); A+B -> score 2 (MEDIUM,
within the spec's 2-3 band); A+B+C -> score 4 (HIGH, confirmed primary
framework). Frameworks with zero evidence are omitted from the result
entirely rather than listed at score 0.

Scoped to the three dominant Python backend frameworks (FastAPI, Flask,
Django) — the registry is intentionally data-driven so more can be added
without touching the scoring logic.
"""

import ast
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from enums import ConfidenceLevel
from utils import DependencyEntry, FrameworkDetection, FrameworkEvidence

_ROUTE_DECORATOR_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "route"})
_DJANGO_CBV_BASES = frozenset({"View", "APIView", "ModelViewSet", "GenericAPIView", "ViewSet"})


def _called_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _fastapi_pattern(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _called_name(node.func) == "FastAPI":
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in _ROUTE_DECORATOR_METHODS
                ):
                    return True
    return False


def _flask_pattern(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _called_name(node.func) == "Flask":
            return True
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if _called_name(base) == "MethodView":
                    return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                ):
                    return True
    return False


def _django_pattern(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "urlpatterns":
                    return True
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if _called_name(base) in _DJANGO_CBV_BASES:
                    return True
    return False


@dataclass(frozen=True)
class FrameworkRule:
    """Detection rule for one framework."""

    name: str
    dependency_names: frozenset[str]
    import_module_names: frozenset[str]
    pattern_matcher: Callable[[ast.Module], bool]


FRAMEWORK_REGISTRY: dict[str, FrameworkRule] = {
    "fastapi": FrameworkRule(
        name="fastapi",
        dependency_names=frozenset({"fastapi"}),
        import_module_names=frozenset({"fastapi"}),
        pattern_matcher=_fastapi_pattern,
    ),
    "flask": FrameworkRule(
        name="flask",
        dependency_names=frozenset({"flask"}),
        import_module_names=frozenset({"flask"}),
        pattern_matcher=_flask_pattern,
    ),
    "django": FrameworkRule(
        name="django",
        dependency_names=frozenset({"django"}),
        import_module_names=frozenset({"django"}),
        pattern_matcher=_django_pattern,
    ),
}


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def extract_imported_modules(tree: ast.Module) -> set[str]:
    """Return the set of top-level module names imported anywhere in ``tree``."""
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


class FrameworkEvidenceCollector:
    """Accumulates Evidence B/C across every successfully-parsed Python file.

    Call ``observe()`` once per file's AST during the scan, then ``finalize()``
    once at the end with the parsed dependency list (Evidence A) to produce
    the scored ``FrameworkDetection`` results.
    """

    def __init__(self) -> None:
        self._import_locations: dict[str, list[str]] = {name: [] for name in FRAMEWORK_REGISTRY}
        self._pattern_locations: dict[str, list[str]] = {name: [] for name in FRAMEWORK_REGISTRY}

    def observe(self, relative_path: str, tree: ast.Module) -> None:
        """Check one file's AST for import/pattern evidence of every registered framework."""
        imported_modules = extract_imported_modules(tree)
        for name, rule in FRAMEWORK_REGISTRY.items():
            if imported_modules & rule.import_module_names:
                self._import_locations[name].append(relative_path)
            if rule.pattern_matcher(tree):
                self._pattern_locations[name].append(relative_path)

    def finalize(self, dependencies: Sequence[DependencyEntry]) -> tuple[FrameworkDetection, ...]:
        """Combine accumulated Evidence B/C with Evidence A to score every framework.

        Args:
            dependencies: Parsed dependency entries (Evidence A source).

        Returns:
            Detected frameworks (score > 0 only), highest score first.
        """
        dependency_by_normalized_name = {_normalize(dep.name): dep for dep in dependencies}

        results: list[FrameworkDetection] = []
        for name, rule in FRAMEWORK_REGISTRY.items():
            matched_dependency = next(
                (
                    dependency_by_normalized_name[dep_name]
                    for dep_name in rule.dependency_names
                    if dep_name in dependency_by_normalized_name
                ),
                None,
            )
            import_hit = bool(self._import_locations[name])
            pattern_hit = bool(self._pattern_locations[name])

            score = 0
            if matched_dependency is not None:
                score += 1
            if import_hit:
                score += 1
            if pattern_hit:
                score += 2

            if score == 0:
                continue

            confidence = (
                ConfidenceLevel.HIGH if score >= 4 else ConfidenceLevel.MEDIUM if score >= 2 else ConfidenceLevel.LOW
            )

            results.append(
                FrameworkDetection(
                    name=name,
                    score=score,
                    confidence=confidence,
                    is_primary=confidence == ConfidenceLevel.HIGH,
                    evidence=FrameworkEvidence(
                        dependency_found=matched_dependency is not None,
                        dependency_source=matched_dependency.source_file if matched_dependency else None,
                        import_found=import_hit,
                        import_locations=tuple(self._import_locations[name]),
                        pattern_found=pattern_hit,
                        pattern_locations=tuple(self._pattern_locations[name]),
                    ),
                )
            )

        return tuple(sorted(results, key=lambda detection: -detection.score))

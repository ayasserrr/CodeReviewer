import ast

from enums import ConfidenceLevel
from helpers.framework_detector import FrameworkEvidenceCollector
from utils import DependencyEntry


def _parse(source: str, filename: str = "test.py") -> ast.Module:
    return ast.parse(source, filename=filename)


class TestFrameworkEvidenceCollector:
    def test_dependency_only_is_low_confidence_not_primary(self):
        collector = FrameworkEvidenceCollector()
        deps = [DependencyEntry(name="fastapi", version=">=0.115", source_file="pyproject.toml")]

        results = collector.finalize(deps)

        assert len(results) == 1
        assert results[0].name == "fastapi"
        assert results[0].score == 1
        assert results[0].confidence == ConfidenceLevel.LOW
        assert results[0].is_primary is False

    def test_dependency_plus_import_is_medium_confidence(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("import fastapi\n")
        collector.observe("app.py", tree)
        deps = [DependencyEntry(name="fastapi", version=None, source_file="pyproject.toml")]

        results = collector.finalize(deps)

        assert results[0].score == 2
        assert results[0].confidence == ConfidenceLevel.MEDIUM
        assert results[0].is_primary is False

    def test_dependency_plus_import_plus_pattern_is_high_confidence_and_primary(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("from fastapi import FastAPI\napp = FastAPI()\n")
        collector.observe("main.py", tree)
        deps = [DependencyEntry(name="fastapi", version=">=0.115", source_file="pyproject.toml")]

        results = collector.finalize(deps)

        assert results[0].score == 4
        assert results[0].confidence == ConfidenceLevel.HIGH
        assert results[0].is_primary is True
        assert results[0].evidence.dependency_found is True
        assert results[0].evidence.dependency_source == "pyproject.toml"
        assert results[0].evidence.import_found is True
        assert results[0].evidence.pattern_found is True

    def test_decorator_pattern_alone_counts_as_evidence_c(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("@app.get('/x')\ndef handler():\n    pass\n")
        collector.observe("routes.py", tree)
        deps = [DependencyEntry(name="fastapi", version=None, source_file="pyproject.toml")]

        results = collector.finalize(deps)
        assert results[0].evidence.pattern_found is True

    def test_no_evidence_at_all_is_omitted_from_results(self):
        collector = FrameworkEvidenceCollector()
        results = collector.finalize([])
        assert results == ()

    def test_undetected_framework_omitted_even_with_other_frameworks_present(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("from fastapi import FastAPI\napp = FastAPI()\nimport fastapi\n")
        collector.observe("main.py", tree)
        deps = [DependencyEntry(name="fastapi", version=None, source_file="pyproject.toml")]

        results = collector.finalize(deps)
        names = {r.name for r in results}
        assert "flask" not in names
        assert "django" not in names

    def test_flask_pattern_detected(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef h():\n    pass\n")
        collector.observe("app.py", tree)
        deps = [DependencyEntry(name="flask", version=None, source_file="requirements.txt")]

        results = collector.finalize(deps)
        assert results[0].name == "flask"
        assert results[0].is_primary is True

    def test_django_urlpatterns_pattern_detected(self):
        collector = FrameworkEvidenceCollector()
        tree = _parse("import django\nurlpatterns = []\n")
        collector.observe("urls.py", tree)
        deps = [DependencyEntry(name="django", version=None, source_file="requirements.txt")]

        results = collector.finalize(deps)
        assert results[0].name == "django"
        assert results[0].is_primary is True

    def test_evidence_locations_accumulate_across_multiple_files(self):
        collector = FrameworkEvidenceCollector()
        collector.observe("a.py", _parse("import fastapi\n"))
        collector.observe("b.py", _parse("import fastapi\n"))
        deps = [DependencyEntry(name="fastapi", version=None, source_file="pyproject.toml")]

        results = collector.finalize(deps)
        assert set(results[0].evidence.import_locations) == {"a.py", "b.py"}

    def test_results_sorted_by_score_descending(self):
        collector = FrameworkEvidenceCollector()
        collector.observe("main.py", _parse("from fastapi import FastAPI\napp = FastAPI()\n"))
        deps = [
            DependencyEntry(name="fastapi", version=None, source_file="pyproject.toml"),
            DependencyEntry(name="flask", version=None, source_file="pyproject.toml"),
        ]

        results = collector.finalize(deps)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

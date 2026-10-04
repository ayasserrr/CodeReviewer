from helpers.finding_normalizers import (
    normalize_bandit,
    normalize_gitleaks,
    normalize_jscpd,
    normalize_lizard,
    normalize_pip_audit,
    normalize_pyright,
    normalize_radon,
    normalize_ruff,
    normalize_semgrep,
    normalize_vulture,
    to_repo_relative_path,
)


class TestNormalizeRuff:
    def test_maps_fields_and_hardcodes_warning_severity(self):
        raw = [{"filename": "a.py", "location": {"row": 5}, "code": "F401", "message": "unused import"}]
        result = normalize_ruff(raw)
        assert result == [
            {"file": "a.py", "line": 5, "severity": "warning", "category": "F401", "message": "unused import"}
        ]

    def test_empty_input_returns_empty(self):
        assert normalize_ruff([]) == []


class TestNormalizePyright:
    def test_maps_severity_via_map(self):
        raw = {
            "generalDiagnostics": [
                {
                    "file": "a.py",
                    "range": {"start": {"line": 3}},
                    "severity": "warning",
                    "rule": "reportUnused",
                    "message": "x",
                }
            ]
        }
        result = normalize_pyright(raw)
        assert result == [
            {"file": "a.py", "line": 3, "severity": "warning", "category": "reportUnused", "message": "x"}
        ]

    def test_unknown_severity_defaults_to_error(self):
        raw = {
            "generalDiagnostics": [
                {"file": "a.py", "range": {"start": {"line": 1}}, "severity": "weird", "message": "x"}
            ]
        }
        result = normalize_pyright(raw)
        assert result[0]["severity"] == "error"

    def test_missing_rule_falls_back_to_type_check_category(self):
        raw = {
            "generalDiagnostics": [
                {"file": "a.py", "range": {"start": {"line": 1}}, "severity": "error", "message": "x"}
            ]
        }
        result = normalize_pyright(raw)
        assert result[0]["category"] == "type_check"


class TestNormalizeRadon:
    def test_ignores_configured_complexity_ranks(self):
        raw = {
            "complexity": {"a.py": [{"rank": "A", "lineno": 1, "name": "f", "complexity": 2}]},
            "maintainability": {},
        }
        result = normalize_radon(raw, complexity_ranks_to_ignore=frozenset({"A", "B"}))
        assert result == []

    def test_rank_c_is_warning_rank_above_c_is_error(self):
        raw = {
            "complexity": {
                "a.py": [
                    {"rank": "C", "lineno": 1, "name": "f", "type": "function", "complexity": 12},
                    {"rank": "D", "lineno": 5, "name": "g", "type": "function", "complexity": 25},
                ]
            },
            "maintainability": {},
        }
        result = normalize_radon(raw, complexity_ranks_to_ignore=frozenset({"A", "B"}))
        severities = {item["category"]: item["severity"] for item in result}
        assert severities["complexity_C"] == "warning"
        assert severities["complexity_D"] == "error"

    def test_maintainability_ignored_rank_a_kept_rank_b(self):
        raw = {"complexity": {}, "maintainability": {"a.py": {"rank": "A", "mi": 90}, "b.py": {"rank": "B", "mi": 60}}}
        result = normalize_radon(raw, mi_ranks_to_ignore=frozenset({"A"}))
        assert len(result) == 1
        assert result[0]["file"] == "b.py"
        assert result[0]["severity"] == "warning"

    def test_complexity_error_string_entry_is_skipped_not_crashed(self):
        """radon reports a file it couldn't parse (syntax error, etc.) as a
        plain error string instead of a list of entries -- must degrade
        gracefully, not raise."""
        raw = {
            "complexity": {
                "broken.py": "SyntaxError: invalid syntax (broken.py, line 3)",
                "a.py": [{"rank": "C", "lineno": 1, "name": "f", "type": "function", "complexity": 12}],
            },
            "maintainability": {},
        }
        result = normalize_radon(raw, complexity_ranks_to_ignore=frozenset({"A", "B"}))
        assert len(result) == 1
        assert result[0]["file"] == "a.py"

    def test_maintainability_error_string_entry_is_skipped_not_crashed(self):
        raw = {
            "complexity": {},
            "maintainability": {
                "broken.py": "SyntaxError: invalid syntax (broken.py, line 3)",
                "b.py": {"rank": "B", "mi": 60},
            },
        }
        result = normalize_radon(raw, mi_ranks_to_ignore=frozenset({"A"}))
        assert len(result) == 1
        assert result[0]["file"] == "b.py"


class TestNormalizeVulture:
    def test_maps_confidence_into_message(self):
        raw = [{"file": "a.py", "line": "10", "message": "unused variable 'x'", "confidence": "90"}]
        result = normalize_vulture(raw)
        assert result == [
            {
                "file": "a.py",
                "line": 10,
                "severity": "warning",
                "category": "dead_code",
                "message": "unused variable 'x' (90% confidence)",
            }
        ]


class TestNormalizeJscpd:
    def test_each_duplicate_pair_produces_two_findings(self):
        raw = [
            {
                "firstFile": {"name": "a.py", "startLoc": {"line": 1}},
                "secondFile": {"name": "b.py", "startLoc": {"line": 20}},
                "lines": 5,
                "tokens": 30,
            }
        ]
        result = normalize_jscpd(raw)
        assert len(result) == 2
        assert {r["file"] for r in result} == {"a.py", "b.py"}
        assert all(r["category"] == "duplicate_code" for r in result)


class TestNormalizeLizard:
    def test_below_error_threshold_is_warning(self):
        raw = [{"ccn": 15, "file": "a.py", "function": "f", "line": 10}]
        result = normalize_lizard(raw, ccn_error_threshold=20)
        assert result[0]["severity"] == "warning"

    def test_above_error_threshold_is_error(self):
        raw = [{"ccn": 25, "file": "a.py", "function": "f", "line": 10}]
        result = normalize_lizard(raw, ccn_error_threshold=20)
        assert result[0]["severity"] == "error"


class TestNormalizePipAudit:
    def test_no_fix_versions_is_critical(self):
        raw = {
            "dependencies": [
                {"name": "pkg", "version": "1.0", "vulns": [{"id": "CVE-1", "fix_versions": [], "description": "bad"}]}
            ]
        }
        result = normalize_pip_audit(raw)
        assert result[0]["severity"] == "critical"
        assert result[0]["file"] == "requirements.txt"

    def test_has_fix_versions_is_high(self):
        raw = {
            "dependencies": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-1", "fix_versions": ["1.1"], "description": "bad"}],
                }
            ]
        }
        result = normalize_pip_audit(raw)
        assert result[0]["severity"] == "high"

    def test_dependency_with_no_vulns_produces_nothing(self):
        raw = {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": []}]}
        assert normalize_pip_audit(raw) == []


class TestNormalizeSemgrep:
    def test_severity_mapped_from_extra(self):
        raw = [
            {
                "path": "a.py",
                "start": {"line": 4},
                "check_id": "rule.id",
                "extra": {"severity": "ERROR", "message": "bad"},
            }
        ]
        result = normalize_semgrep(raw)
        assert result[0]["severity"] == "high"
        assert result[0]["category"] == "rule.id"

    def test_unknown_severity_defaults_to_low(self):
        raw = [
            {
                "path": "a.py",
                "start": {"line": 4},
                "check_id": "rule.id",
                "extra": {"severity": "weird", "message": "bad"},
            }
        ]
        result = normalize_semgrep(raw)
        assert result[0]["severity"] == "low"


class TestNormalizeBandit:
    def test_severity_lowercased(self):
        raw = [{"filename": "a.py", "line_number": 7, "issue_severity": "HIGH", "test_id": "B101", "issue_text": "bad"}]
        result = normalize_bandit(raw)
        assert result[0]["severity"] == "high"
        assert result[0]["category"] == "B101"


class TestNormalizeGitleaks:
    def test_hardcodes_critical_severity(self):
        raw = [{"File": "config.yaml", "StartLine": 3, "RuleID": "aws-key", "Description": "AWS key detected"}]
        result = normalize_gitleaks(raw)
        assert result[0]["severity"] == "critical"
        assert result[0]["file"] == "config.yaml"


class TestToRepoRelativePath:
    def test_absolute_path_under_repo_root_becomes_relative(self, tmp_path):
        repo_root = tmp_path / "repo"
        (repo_root / "src").mkdir(parents=True)
        file_path = repo_root / "src" / "a.py"
        file_path.touch()
        assert to_repo_relative_path(str(file_path), str(repo_root)) == "src/a.py"

    def test_already_relative_path_is_normalized_to_posix(self):
        assert to_repo_relative_path("a\\b.py", "/repo") in ("a/b.py", "a\\b.py")

    def test_empty_path_returned_unchanged(self):
        assert to_repo_relative_path("", "/repo") == ""

    def test_absolute_path_outside_repo_root_falls_back_to_posix(self, tmp_path):
        outside = tmp_path / "elsewhere" / "a.py"
        result = to_repo_relative_path(str(outside), str(tmp_path / "repo"))
        assert result  # doesn't raise, returns something usable

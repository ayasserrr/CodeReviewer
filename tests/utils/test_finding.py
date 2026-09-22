from utils import StaticFinding


class TestStaticFindingFromNormalized:
    def test_identical_input_produces_identical_id(self):
        data = {"file": "a.py", "line": 10, "severity": "warning", "category": "F401", "message": "unused import"}
        f1 = StaticFinding.from_normalized("ruff", data)
        f2 = StaticFinding.from_normalized("ruff", dict(data))
        assert f1.id == f2.id

    def test_different_tool_produces_different_id(self):
        data = {"file": "a.py", "line": 10, "severity": "warning", "category": "F401", "message": "unused import"}
        f1 = StaticFinding.from_normalized("ruff", data)
        f2 = StaticFinding.from_normalized("other-tool", data)
        assert f1.id != f2.id

    def test_different_line_produces_different_id(self):
        base = {"file": "a.py", "severity": "warning", "category": "F401", "message": "unused import"}
        f1 = StaticFinding.from_normalized("ruff", {**base, "line": 10})
        f2 = StaticFinding.from_normalized("ruff", {**base, "line": 11})
        assert f1.id != f2.id

    def test_id_is_16_hex_chars(self):
        data = {"file": "a.py", "line": 10, "severity": "warning", "category": "F401", "message": "unused import"}
        finding = StaticFinding.from_normalized("ruff", data)
        assert len(finding.id) == 16
        assert all(c in "0123456789abcdef" for c in finding.id)

    def test_is_frozen(self):
        data = {"file": "a.py", "line": 10, "severity": "warning", "category": "F401", "message": "unused import"}
        finding = StaticFinding.from_normalized("ruff", data)
        try:
            finding.file = "b.py"
            assert False, "expected FrozenInstanceError"
        except AttributeError:
            pass

    def test_none_line_is_stable_in_id(self):
        data = {"file": "requirements.txt", "line": None, "severity": "critical", "category": "CVE-1", "message": "bad"}
        f1 = StaticFinding.from_normalized("pip_audit", data)
        f2 = StaticFinding.from_normalized("pip_audit", dict(data))
        assert f1.id == f2.id
        assert f1.line is None

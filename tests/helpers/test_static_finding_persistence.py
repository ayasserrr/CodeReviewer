from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from helpers.static_finding_persistence import save_static_findings
from utils import StaticFinding


def _make_finding(tool: str = "ruff") -> StaticFinding:
    return StaticFinding.from_normalized(
        tool, {"file": "a.py", "line": 1, "severity": "warning", "category": "F401", "message": "unused import"}
    )


class TestSaveStaticFindings:
    async def test_empty_findings_skips_repository_call_entirely(self):
        mock_repo = MagicMock()
        mock_repo.bulk_upsert = AsyncMock()
        await save_static_findings(mock_repo, repository_id=uuid4(), head_sha="a" * 40, findings=[])
        mock_repo.bulk_upsert.assert_not_awaited()

    async def test_builds_rows_with_tool_and_all_fields(self):
        mock_repo = MagicMock()
        mock_repo.bulk_upsert = AsyncMock(return_value=1)
        repository_id = uuid4()
        finding = _make_finding("bandit")

        await save_static_findings(mock_repo, repository_id=repository_id, head_sha="a" * 40, findings=[finding])

        mock_repo.bulk_upsert.assert_awaited_once()
        rows = mock_repo.bulk_upsert.call_args.args[0]
        assert len(rows) == 1
        row = rows[0]
        assert row["repository_id"] == repository_id
        assert row["head_sha"] == "a" * 40
        assert row["finding_id"] == finding.id
        assert row["tool"] == "bandit"
        assert row["file"] == "a.py"
        assert row["line"] == 1
        assert row["severity"] == "warning"
        assert row["category"] == "F401"
        assert row["message"] == "unused import"

    async def test_multiple_findings_from_different_tools_all_included(self):
        mock_repo = MagicMock()
        mock_repo.bulk_upsert = AsyncMock(return_value=2)
        findings = [_make_finding("ruff"), _make_finding("bandit")]

        await save_static_findings(mock_repo, repository_id=uuid4(), head_sha="a" * 40, findings=findings)

        rows = mock_repo.bulk_upsert.call_args.args[0]
        assert {row["tool"] for row in rows} == {"ruff", "bandit"}

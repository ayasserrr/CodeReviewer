"""Tests for StaticFindingRepository.bulk_upsert's batching.

Regression coverage for a real production failure: a noisy real-world
repository's first-ever scan produced enough findings that one unbatched
INSERT exceeded asyncpg's 32767-bind-parameter limit
(``InterfaceError: the number of query arguments cannot exceed 32767``).
"""

from unittest.mock import AsyncMock, MagicMock

from data.repositories.static_finding_repository import _UPSERT_BATCH_SIZE, StaticFindingRepository


def _row(i: int) -> dict:
    return {
        "repository_id": "r",
        "head_sha": "sha",
        "finding_id": f"f{i}",
        "tool": "ruff",
        "file": "a.py",
        "line": i,
        "severity": "warning",
        "category": "F401",
        "message": "unused import",
    }


def _repo_with_session(rowcounts: list[int]) -> tuple[StaticFindingRepository, MagicMock]:
    session = MagicMock()
    results = iter(rowcounts)
    session.execute = AsyncMock(side_effect=lambda *_a, **_k: MagicMock(rowcount=next(results)))
    session.flush = AsyncMock()
    return StaticFindingRepository(session), session


class TestBulkUpsertBatching:
    async def test_empty_rows_never_calls_execute(self):
        repo, session = _repo_with_session([])
        assert await repo.bulk_upsert([]) == 0
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    async def test_rows_under_batch_size_use_a_single_statement(self):
        repo, session = _repo_with_session([5])
        rows = [_row(i) for i in range(5)]

        inserted = await repo.bulk_upsert(rows)

        assert inserted == 5
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    async def test_rows_over_the_asyncpg_bind_parameter_limit_are_split_into_batches(self):
        """The real bug: 10 params/row * 3277+ rows in one statement exceeds
        asyncpg's 32767 limit. This count would have crashed unbatched."""
        total_rows = (_UPSERT_BATCH_SIZE * 3) + 277  # 3 full batches + one partial
        repo, session = _repo_with_session([_UPSERT_BATCH_SIZE, _UPSERT_BATCH_SIZE, _UPSERT_BATCH_SIZE, 277])
        rows = [_row(i) for i in range(total_rows)]

        inserted = await repo.bulk_upsert(rows)

        assert inserted == total_rows
        assert session.execute.await_count == 4
        session.flush.assert_awaited_once()  # one flush for the whole transaction, not per batch

    async def test_conflicts_within_a_batch_are_excluded_from_the_inserted_count(self):
        """rowcount reflects ON CONFLICT DO NOTHING skips -- some rows in a
        batch may already exist from a prior run at the same commit."""
        repo, _session = _repo_with_session([3])  # 5 rows sent, only 3 actually inserted
        rows = [_row(i) for i in range(5)]

        assert await repo.bulk_upsert(rows) == 3

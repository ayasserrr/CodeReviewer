"""Repository for ``repositories`` table CRUD operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from data.models import Repository


class RepositoryRepository:
    """Encapsulates all database operations for the ``Repository`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def get(self, repository_id: UUID) -> Repository | None:
        """Fetch a single repository by primary key.

        Args:
            repository_id: UUID of the repository to retrieve.

        Returns:
            The ``Repository`` instance, or ``None`` if not found.
        """
        return await self._db_session.get(Repository, repository_id)

    async def get_all_by_user_id(self, user_id: UUID, page: int = 1, page_size: int = 20) -> list[Repository]:
        """Fetch a paginated list of repositories owned by a user.

        Args:
            user_id: UUID of the owning user.
            page: 1-based page number.
            page_size: Number of records per page.

        Returns:
            List of ``Repository`` instances for the requested page; empty list if none exist.
        """
        offset = (page - 1) * page_size
        result = await self._db_session.execute(
            select(Repository).where(Repository.user_id == user_id).offset(offset).limit(page_size)
        )
        return list(result.scalars().all())

    async def create(self, **kwargs) -> Repository:
        """Insert a new repository row.

        Args:
            **kwargs: Column values matching ``Repository`` ORM fields
                (e.g. ``user_id``, ``name``, ``clone_url``).

        Returns:
            The newly created ``Repository`` instance after flush.
        """
        repository = Repository(**kwargs)
        self._db_session.add(repository)
        await self._db_session.flush()
        return repository

    async def update(self, repository_id: UUID, **kwargs) -> Repository | None:
        """Apply a partial update to an existing repository.

        Only keys present in ``kwargs`` are written; ``None`` values are
        skipped so callers can pass ``RepositoryUpdate.model_dump(exclude_unset=True)``.

        Args:
            repository_id: UUID of the repository to update.
            **kwargs: Column-value pairs to update.

        Returns:
            The updated ``Repository`` instance, or ``None`` if not found.
        """
        repository = await self.get(repository_id)
        if repository is None:
            return None
        for key, value in kwargs.items():
            if value is not None:
                setattr(repository, key, value)
        await self._db_session.flush()
        return repository

    async def delete(self, repository_id: UUID) -> bool:
        """Delete a repository by primary key.

        Args:
            repository_id: UUID of the repository to delete.

        Returns:
            ``True`` if the repository was deleted, ``False`` if not found.
        """
        repository = await self.get(repository_id)
        if repository is None:
            return False
        await self._db_session.delete(repository)
        await self._db_session.flush()
        return True

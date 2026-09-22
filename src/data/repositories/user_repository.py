"""Repository for ``users`` table CRUD operations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from data.models import User


class UserRepository:
    """Encapsulates all database operations for the ``User`` ORM model.

    Receives an ``AsyncSession`` so multiple repositories can share a single
    transaction per request.

    Args:
        db_session: Active async database session.
    """

    def __init__(self, db_session: AsyncSession) -> None:
        self._db_session = db_session

    async def get(self, user_id: UUID) -> User | None:
        """Fetch a single user by primary key.

        Args:
            user_id: UUID of the user to retrieve.

        Returns:
            The ``User`` instance, or ``None`` if not found.
        """
        return await self._db_session.get(User, user_id)

    async def get_by_email(self, email: str) -> User | None:
        """Fetch a single user by email address.

        Args:
            email: Email address to look up.

        Returns:
            The ``User`` instance, or ``None`` if not found.
        """

        result = await self._db_session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_all(self, page: int = 1, page_size: int = 20) -> list[User]:
        """Fetch a paginated list of all users.

        Args:
            page: 1-based page number.
            page_size: Number of records per page.

        Returns:
            List of ``User`` instances for the requested page; empty list if none exist.
        """
        offset = (page - 1) * page_size
        result = await self._db_session.execute(select(User).offset(offset).limit(page_size))
        return list(result.scalars().all())

    async def create(self, **kwargs) -> User:
        """Insert a new user row.

        Caller is responsible for hashing the password before passing
        ``hashed_password`` — this method never receives plain-text credentials.

        Args:
            **kwargs: Column values matching ``User`` ORM fields
                (e.g. ``email``, ``hashed_password``).

        Returns:
            The newly created ``User`` instance after flush.
        """
        user = User(**kwargs)
        self._db_session.add(user)
        await self._db_session.flush()
        return user

    async def update(self, user_id: UUID, **kwargs) -> User | None:
        """Apply a partial update to an existing user.

        Only keys present in ``kwargs`` are written; ``None`` values are
        skipped so callers can pass ``UserUpdate.model_dump(exclude_unset=True)``.

        Args:
            user_id: UUID of the user to update.
            **kwargs: Column-value pairs to update.

        Returns:
            The updated ``User`` instance, or ``None`` if not found.
        """
        user = await self.get(user_id)
        if user is None:
            return None
        for key, value in kwargs.items():
            if value is not None:
                setattr(user, key, value)
        await self._db_session.flush()
        return user

    async def delete(self, user_id: UUID) -> bool:
        """Delete a user by primary key.

        Args:
            user_id: UUID of the user to delete.

        Returns:
            ``True`` if the user was deleted, ``False`` if not found.
        """
        user = await self.get(user_id)
        if user is None:
            return False
        await self._db_session.delete(user)
        await self._db_session.flush()
        return True

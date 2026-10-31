"""
User repository.

Isolates ALL database queries for the User model behind a small interface.
`app/services/auth_service.py` depends on this, not on SQLAlchemy directly —
that's what makes the service layer unit-testable with a fake/mock
repository instead of a real database.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserRepository:
    def __init__(self, db: AsyncSession):
        self._db = db

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self._db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        result = await self._db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create(self, *, email: str, full_name: str, hashed_password: str, role: str = "analyst") -> User:
        user = User(
            email=email,
            full_name=full_name,
            hashed_password=hashed_password,
            role=role,
        )
        self._db.add(user)
        await self._db.flush()
        await self._db.refresh(user)
        return user

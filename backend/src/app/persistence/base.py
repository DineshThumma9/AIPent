"""Base repository helpers shared by all persistence modules."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select


class BaseRepo:
    """Thin wrapper around an async session.

    Repositories should not own transactions — the caller (service, agent,
    route) decides when to commit. Each repo method receives the session it
    should operate on.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get(self, model: Any, id_value: Any) -> Any | None:
        return await self.session.get(model, id_value)

    async def execute(self, statement: Any):
        return await self.session.execute(statement)

    async def add(self, instance: Any) -> None:
        self.session.add(instance)

    async def flush(self) -> None:
        await self.session.flush()

    async def commit(self) -> None:
        await self.session.commit()

    async def refresh(self, instance: Any) -> None:
        await self.session.refresh(instance)

    def _apply_filters(
        self,
        statement: Any,
        filters: dict[str, Any] | None,
        like_filters: dict[str, str] | None = None,
    ) -> Any:
        """Optionally apply equality and ILIKE filters to a statement."""
        if filters:
            for key, value in filters.items():
                if value is not None:
                    statement = statement.where(getattr(statement.columns, key) == value)
        if like_filters:
            for key, pattern in like_filters.items():
                statement = statement.where(getattr(statement.columns, key).ilike(f"%{pattern}%"))
        return statement

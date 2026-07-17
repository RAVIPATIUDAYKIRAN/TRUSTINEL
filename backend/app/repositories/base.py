from typing import Any, Type, TypeVar, Optional
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar('T')


class BaseRepository:
    """
    Generic Base Repository providing common database CRUD helpers using AsyncSession.
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def add(self, model_instance: Any) -> None:
        """
        Add a model instance to the current session tracking.
        """
        self.session.add(model_instance)

    async def get_by_id(self, model_class: Type[T], id_: Any) -> Optional[T]:
        """
        Retrieve a record by its primary key value.
        """
        return await self.session.get(model_class, id_)

    async def delete(self, model_instance: Any) -> None:
        """
        Mark a model instance for deletion.
        """
        await self.session.delete(model_instance)

    async def flush(self) -> None:
        """
        Flush pending state changes to the database.
        """
        await self.session.flush()

    async def commit(self) -> None:
        """
        Commit the current active database transaction.
        """
        await self.session.commit()

    async def refresh(self, model_instance: Any) -> None:
        """
        Refresh the attributes of the model instance from the database state.
        """
        await self.session.refresh(model_instance)

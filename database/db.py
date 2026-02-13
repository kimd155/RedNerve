from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from config import Config

engine = create_async_engine(Config.DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    from database.models import Base  # noqa: F811
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await _migrate_db()


async def _migrate_db():
    """Add columns that may not exist in older databases."""
    import sqlalchemy as sa
    async with engine.begin() as conn:
        # Add beacon_id to sessions if missing
        try:
            await conn.execute(sa.text(
                "ALTER TABLE sessions ADD COLUMN beacon_id VARCHAR(36)"
            ))
        except Exception:
            pass

        # Backfill task beacon_id from params JSON
        try:
            await conn.execute(sa.text(
                "UPDATE tasks SET beacon_id = json_extract(params, '$.beacon_id') "
                "WHERE beacon_id IS NULL AND json_extract(params, '$.beacon_id') IS NOT NULL"
            ))
        except Exception:
            pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session

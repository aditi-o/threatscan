"""
Database configuration for SafeLink Shield.
Uses SQLAlchemy async with SQLite or PostgreSQL.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# Create async engine with appropriate settings for SQLite vs PostgreSQL
_db_url = settings.async_database_url

engine = create_async_engine(
    _db_url,
    echo=False,  # Set to True for SQL debugging
    future=True,
    # Only use pool_pre_ping for PostgreSQL (not SQLite)
    pool_pre_ping=not settings.is_sqlite,
)

print(f"📊 Database: {'SQLite (local)' if settings.is_sqlite else 'PostgreSQL'}")

# Create async session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base class for all models
Base = declarative_base()


async def create_db():
    """
    Create all database tables.
    Called on application startup.
    """
    async with engine.begin() as conn:
        # Import models to ensure they're registered with Base
        from app import models  # noqa
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created successfully")


async def get_db():
    """
    Dependency that provides a database session.
    Use with FastAPI's Depends().
    """
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

"""
Database configuration for SafeLink Shield.
Uses SQLAlchemy async with SQLite (aiosqlite).
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# Create async engine for SQLite
# echo=True logs all SQL statements (useful for debugging)
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    future=True
)

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

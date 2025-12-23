"""
Database configuration for SafeLink Shield.
Uses SQLAlchemy async with SQLite or PostgreSQL.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# Create async engine
# Use async_database_url to handle URL conversion for PostgreSQL
engine = create_async_engine(
    settings.async_database_url,
    echo=False,  # Set to True for SQL debugging
    future=True,
    # PostgreSQL specific settings
    pool_pre_ping=True if "postgresql" in settings.async_database_url else False,
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

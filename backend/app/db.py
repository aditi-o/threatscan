"""
Database configuration for SafeLink Shield.
Uses SQLAlchemy async with SQLite (dev) or PostgreSQL (production).
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

_db_url = settings.async_database_url

if settings.is_sqlite:
    print("📊 Database: SQLite (local development)")
    # SQLite doesn't support pool settings
    engine = create_async_engine(
        _db_url,
        echo=False,
        future=True,
    )
else:
    print("📊 Database: PostgreSQL (production)")
    # PostgreSQL with connection pooling
    engine = create_async_engine(
        _db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
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
    try:
        async with engine.begin() as conn:
            from app import models  # noqa
            await conn.run_sync(Base.metadata.create_all)
        print("✅ Database tables created successfully")
    except Exception as e:
        error_msg = str(e).lower()
        print(f"\n❌ DATABASE ERROR: {e}")
        
        if "getaddrinfo failed" in error_msg or "could not translate host name" in error_msg:
            print("   → Cannot resolve hostname. Check DATABASE_URL or network connection.")
        elif "password authentication failed" in error_msg:
            print("   → Invalid credentials in DATABASE_URL.")
        elif "connection refused" in error_msg:
            print("   → PostgreSQL server not running or wrong port.")
        
        if not settings.is_sqlite:
            print("\n💡 Tip: Remove DATABASE_URL from .env to use SQLite for local development.")
        raise


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

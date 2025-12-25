"""
Database configuration for SafeLink Shield.
Uses SQLAlchemy async with PostgreSQL (required for production).
"""

import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# Validate DATABASE_URL is set for production
_db_url = settings.async_database_url

if settings.is_sqlite:
    print("⚠️  WARNING: Using SQLite (development only). Set DATABASE_URL for production.")
else:
    print(f"📊 Database: PostgreSQL")

# Create async engine with appropriate settings
engine = create_async_engine(
    _db_url,
    echo=False,  # Set to True for SQL debugging
    future=True,
    pool_pre_ping=not settings.is_sqlite,
    # Connection pool settings for PostgreSQL
    pool_size=5 if not settings.is_sqlite else 0,
    max_overflow=10 if not settings.is_sqlite else 0,
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
            # Import models to ensure they're registered with Base
            from app import models  # noqa
            await conn.run_sync(Base.metadata.create_all)
        print("✅ Database tables created successfully")
    except Exception as e:
        error_msg = str(e)
        if "getaddrinfo failed" in error_msg or "could not translate host name" in error_msg:
            print(f"❌ DATABASE CONNECTION ERROR: Cannot resolve database hostname.")
            print(f"   Check your DATABASE_URL in .env file:")
            print(f"   - Verify the hostname is correct")
            print(f"   - Ensure you have network connectivity")
            print(f"   - For Supabase: use the 'Connection string' from Project Settings > Database")
        elif "password authentication failed" in error_msg:
            print(f"❌ DATABASE AUTH ERROR: Invalid username or password in DATABASE_URL")
        elif "Connection refused" in error_msg:
            print(f"❌ DATABASE CONNECTION ERROR: Server refused connection. Is PostgreSQL running?")
        else:
            print(f"❌ DATABASE ERROR: {error_msg}")
        
        print("\n💡 Example DATABASE_URL format:")
        print("   postgresql://user:password@host:5432/database")
        print("   postgresql://postgres:yourpassword@db.xxxx.supabase.co:5432/postgres")
        sys.exit(1)


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

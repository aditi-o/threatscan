"""
CRUD (Create, Read, Update, Delete) operations for database models.
All operations are async for better performance.
"""

from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from app.models import User, ScanHistory, Report, ScanFeedback
from app.schemas import UserCreate, ReportCreate, FeedbackCreate

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ========================
# User CRUD
# ========================

async def create_user(db: AsyncSession, user: UserCreate) -> User:
    """
    Create a new user with hashed password.
    """
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        name=user.name,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """
    Get user by email address.
    """
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    """
    Get user by ID.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)


# ========================
# Scan History CRUD
# ========================

async def create_scan(
    db: AsyncSession,
    user_id: Optional[int],
    input_type: str,
    input_text: str,
    result_json: dict,
    model_version: str = "v1.0"
) -> ScanHistory:
    """
    Create a new scan history record.
    """
    db_scan = ScanHistory(
        user_id=user_id,
        input_type=input_type,
        input_text=input_text,
        result_json=result_json,
        model_version=model_version
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    return db_scan


async def get_history_by_user(
    db: AsyncSession,
    user_id: int,
    limit: int = 50
) -> List[ScanHistory]:
    """
    Get scan history for a specific user.
    """
    result = await db.execute(
        select(ScanHistory)
        .where(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


async def get_all_scans(db: AsyncSession, limit: int = 100) -> List[ScanHistory]:
    """
    Get all scan history (for admin).
    """
    result = await db.execute(
        select(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


# ========================
# Report CRUD
# ========================

async def create_report(
    db: AsyncSession,
    user_id: Optional[int],
    report: ReportCreate
) -> Report:
    """
    Create a new scam report.
    """
    db_report = Report(
        user_id=user_id,
        input_type=report.input_type,
        input_text=report.input_text,
        comment=report.comment
    )
    db.add(db_report)
    await db.commit()
    await db.refresh(db_report)
    return db_report


async def get_reports(
    db: AsyncSession,
    status: Optional[str] = None,
    limit: int = 100
) -> List[Report]:
    """
    Get reports, optionally filtered by status.
    """
    query = select(Report).order_by(Report.created_at.desc()).limit(limit)
    if status:
        query = query.where(Report.status == status)
    result = await db.execute(query)
    return result.scalars().all()


async def update_report_status(
    db: AsyncSession,
    report_id: int,
    status: str
) -> Optional[Report]:
    """
    Update report status (for admin review).
    """
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if report:
        report.status = status
        await db.commit()
        await db.refresh(report)
    return report


# ========================
# Feedback CRUD
# ========================

async def create_feedback(
    db: AsyncSession,
    user_id: Optional[int],
    feedback: FeedbackCreate
) -> ScanFeedback:
    """
    Create a new scan feedback record.
    """
    db_feedback = ScanFeedback(
        scan_id=feedback.scan_id,
        user_id=user_id,
        input_type=feedback.input_type,
        input_text=feedback.input_text,
        original_verdict=feedback.original_verdict,
        user_verdict=feedback.user_verdict,
        feedback_type=feedback.feedback_type,
        comment=feedback.comment
    )
    db.add(db_feedback)
    await db.commit()
    await db.refresh(db_feedback)
    return db_feedback


async def get_feedback_stats(db: AsyncSession) -> dict:
    """
    Get feedback statistics for model improvement insights.
    """
    from sqlalchemy import func
    
    # Count by feedback type
    type_counts = await db.execute(
        select(
            ScanFeedback.feedback_type,
            func.count(ScanFeedback.id).label("count")
        ).group_by(ScanFeedback.feedback_type)
    )
    counts = {row[0]: row[1] for row in type_counts}
    
    # Count pending reviews
    pending = await db.execute(
        select(func.count(ScanFeedback.id))
        .where(ScanFeedback.status == "pending")
    )
    
    return {
        "total_feedback": sum(counts.values()),
        "false_positives": counts.get("false_positive", 0),
        "false_negatives": counts.get("false_negative", 0),
        "correct": counts.get("correct", 0),
        "pending_review": pending.scalar() or 0
    }


async def get_all_feedback(
    db: AsyncSession,
    feedback_type: Optional[str] = None,
    limit: int = 100
) -> List[ScanFeedback]:
    """
    Get all feedback records, optionally filtered by type.
    """
    query = select(ScanFeedback).order_by(ScanFeedback.created_at.desc()).limit(limit)
    if feedback_type:
        query = query.where(ScanFeedback.feedback_type == feedback_type)
    result = await db.execute(query)
    return result.scalars().all()

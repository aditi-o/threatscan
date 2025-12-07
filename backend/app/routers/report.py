"""
Report router for SafeLink Shield.
Handles user-submitted scam reports.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.schemas import ReportCreate, ReportOut
from app.crud import create_report, get_reports
from app.routers.auth import get_current_user, get_optional_user

router = APIRouter(prefix="/report", tags=["Reports"])


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def submit_report(
    report: ReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Submit a scam report.
    
    Users can report suspicious content they've encountered.
    """
    # Validate input
    if not report.input_text or len(report.input_text.strip()) < 5:
        raise HTTPException(
            status_code=400,
            detail="Report content is too short"
        )
    
    if report.input_type not in ["url", "text", "screenshot", "audio"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid input type. Must be: url, text, screenshot, or audio"
        )
    
    user_id = current_user.id if current_user else None
    db_report = await create_report(db, user_id, report)
    
    return db_report


@router.get("", response_model=List[ReportOut])
async def list_reports(
    status_filter: str = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List all reports (admin only).
    
    TODO: Add proper admin role check.
    """
    reports = await get_reports(db, status=status_filter, limit=limit)
    return reports


@router.get("/my", response_model=List[ReportOut])
async def list_my_reports(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List reports submitted by current user.
    """
    from sqlalchemy import select
    from app.models import Report
    
    result = await db.execute(
        select(Report)
        .where(Report.user_id == current_user.id)
        .order_by(Report.created_at.desc())
        .limit(50)
    )
    return result.scalars().all()

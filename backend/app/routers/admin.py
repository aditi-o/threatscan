"""
Admin router for SafeLink Shield.
Handles administrative functions like report review and stats.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db import get_db
from app.models import ScanHistory, Report, User
from app.schemas import ScanHistoryOut, ReportOut
from app.routers.auth import get_current_user
from app.crud import update_report_status, get_all_scans

router = APIRouter(prefix="/admin", tags=["Admin"])


# TODO: Implement proper admin role checking
async def require_admin(current_user = Depends(get_current_user)):
    """
    Dependency to require admin privileges.
    Currently placeholder - implement proper role system.
    """
    # For now, all authenticated users have access
    # In production, check user.role == "admin"
    return current_user


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    admin = Depends(require_admin)
):
    """
    Get platform statistics.
    """
    # Count total scans by type
    scan_counts = await db.execute(
        select(
            ScanHistory.input_type,
            func.count(ScanHistory.id).label("count")
        ).group_by(ScanHistory.input_type)
    )
    scan_by_type = {row[0]: row[1] for row in scan_counts}
    
    # Count total users
    user_count = await db.execute(select(func.count(User.id)))
    total_users = user_count.scalar()
    
    # Count reports by status
    report_counts = await db.execute(
        select(
            Report.status,
            func.count(Report.id).label("count")
        ).group_by(Report.status)
    )
    reports_by_status = {row[0]: row[1] for row in report_counts}
    
    # Count total scans
    total_scans = await db.execute(select(func.count(ScanHistory.id)))
    
    return {
        "total_users": total_users,
        "total_scans": total_scans.scalar(),
        "scans_by_type": scan_by_type,
        "reports_by_status": reports_by_status
    }


@router.get("/scans", response_model=List[ScanHistoryOut])
async def list_all_scans(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    admin = Depends(require_admin)
):
    """
    List all scan history (for review).
    """
    scans = await get_all_scans(db, limit=limit)
    return scans


@router.patch("/report/{report_id}/status")
async def update_report(
    report_id: int,
    status: str,
    db: AsyncSession = Depends(get_db),
    admin = Depends(require_admin)
):
    """
    Update a report's status.
    
    Status options: pending, reviewed, confirmed, rejected
    """
    valid_statuses = ["pending", "reviewed", "confirmed", "rejected"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    report = await update_report_status(db, report_id, status)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {"message": "Report status updated", "report_id": report_id, "status": status}


# ========================
# TODO: Scam Template Management
# ========================

@router.get("/templates")
async def list_templates(admin = Depends(require_admin)):
    """
    List scam detection templates.
    TODO: Implement template storage and management.
    """
    return {
        "message": "Template management coming soon",
        "templates": []
    }


@router.post("/templates")
async def create_template(admin = Depends(require_admin)):
    """
    Create a new scam detection template.
    TODO: Implement template creation.
    """
    return {"message": "Template creation coming soon"}


@router.delete("/templates/{template_id}")
async def delete_template(template_id: int, admin = Depends(require_admin)):
    """
    Delete a scam detection template.
    TODO: Implement template deletion.
    """
    return {"message": f"Template {template_id} deletion coming soon"}

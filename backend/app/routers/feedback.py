"""
Feedback router for SafeLink Shield.
Handles user feedback on scan results for model improvement.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.schemas import FeedbackCreate, FeedbackOut, FeedbackStats
from app.crud import create_feedback, get_feedback_stats, get_all_feedback
from app.routers.auth import get_current_user, get_optional_user

router = APIRouter(prefix="/feedback", tags=["Feedback"])


@router.post("", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    feedback: FeedbackCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Submit feedback on a scan result.
    
    Users can report false positives or false negatives to help
    improve the detection model over time.
    """
    # Validate verdicts
    valid_verdicts = ["safe", "suspicious", "malicious"]
    if feedback.original_verdict not in valid_verdicts:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid original_verdict. Must be one of: {valid_verdicts}"
        )
    if feedback.user_verdict not in valid_verdicts:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid user_verdict. Must be one of: {valid_verdicts}"
        )
    
    # Validate input
    if not feedback.input_text or len(feedback.input_text.strip()) < 3:
        raise HTTPException(
            status_code=400,
            detail="Input text is too short"
        )
    
    if feedback.input_type not in ["url", "text", "screenshot", "audio"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid input type. Must be: url, text, screenshot, or audio"
        )
    
    user_id = current_user.id if current_user else None
    db_feedback = await create_feedback(db, user_id, feedback)
    
    return db_feedback


@router.get("/stats", response_model=FeedbackStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get feedback statistics.
    
    Shows counts of false positives, false negatives, and correct
    classifications to understand model performance.
    """
    stats = await get_feedback_stats(db)
    return stats


@router.get("", response_model=List[FeedbackOut])
async def list_feedback(
    feedback_type: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    List all feedback records.
    
    Can filter by feedback_type: false_positive, false_negative, correct
    """
    if feedback_type and feedback_type not in ["false_positive", "false_negative", "correct"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid feedback_type. Must be: false_positive, false_negative, or correct"
        )
    
    feedback_list = await get_all_feedback(db, feedback_type=feedback_type, limit=limit)
    return feedback_list

"""
Pydantic schemas for request/response validation.
Defines data transfer objects (DTOs) for the API.
"""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr


# ========================
# User Schemas
# ========================

class UserCreate(BaseModel):
    """Schema for user registration."""
    name: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    """Schema for user response (excludes password)."""
    id: int
    name: str
    email: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


# ========================
# Auth Schemas
# ========================

class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Data encoded in JWT token."""
    email: Optional[str] = None
    user_id: Optional[int] = None


# ========================
# Scan Schemas
# ========================

class ScanRequest(BaseModel):
    """Base schema for scan requests."""
    content: str  # URL or text to scan


class ScanResponse(BaseModel):
    """Response schema for all scan types."""
    input_type: str
    input_text: str
    risk_score: int  # 0-100
    label: str  # Category label
    is_safe: bool
    reasons: List[str]  # Explanation bullets
    suggestions: List[str]  # Safety recommendations
    model_version: str
    scan_id: Optional[int] = None


class AudioScanResponse(ScanResponse):
    """Response schema for audio scans (includes transcript)."""
    transcript: str


class ScreenshotScanResponse(ScanResponse):
    """Response schema for screenshot scans (includes extracted text)."""
    extracted_text: str


# ========================
# Chat Schemas
# ========================

class ChatRequest(BaseModel):
    """Schema for chatbot requests."""
    message: str
    conversation_id: Optional[str] = None


class ChatResponse(BaseModel):
    """Schema for chatbot responses."""
    response: str
    conversation_id: str


# ========================
# Report Schemas
# ========================

class ReportCreate(BaseModel):
    """Schema for creating a scam report."""
    input_type: str
    input_text: str
    comment: Optional[str] = None


class ReportOut(BaseModel):
    """Schema for report response."""
    id: int
    input_type: str
    input_text: str
    comment: Optional[str]
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========================
# History Schemas
# ========================

class ScanHistoryOut(BaseModel):
    """Schema for scan history response."""
    id: int
    input_type: str
    input_text: str
    result_json: Any
    model_version: str
    created_at: datetime
    
    class Config:
        from_attributes = True

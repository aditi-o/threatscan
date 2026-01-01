"""
Pydantic schemas for request/response validation.
Defines data transfer objects (DTOs) for the API.
"""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, Field


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
    """
    Base schema for scan requests.
    Accepts 'content', 'url', or 'text' fields for flexibility.
    Supports 'language' for multilingual explanations.
    """
    content: Optional[str] = None
    url: Optional[str] = None  # Alternative for URL scans
    text: Optional[str] = None  # Alternative for text scans
    language: str = "en"  # Language for explanations: en, hi, mr
    
    def get_content(self) -> str:
        """Get the content to scan from any of the accepted fields."""
        return self.content or self.url or self.text or ""
    
    def get_language(self) -> str:
        """Get the language, defaulting to English if invalid."""
        valid_languages = ["en", "hi", "mr"]
        return self.language if self.language in valid_languages else "en"


class UrlBreakdown(BaseModel):
    """Schema for URL decomposition."""
    full_host: str
    subdomain: str
    domain: str
    tld: str
    is_ip: bool = False
    registered_domain: str
    path: str = "/"
    port: str = ""


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
    
    # New explainability fields
    attack_patterns: List[str] = []  # Detected attack patterns
    url_breakdown: Optional[UrlBreakdown] = None  # URL decomposition
    explanation: Optional[str] = None  # Summary explanation
    safety_tip: Optional[str] = None  # Educational tip
    language: str = "en"  # Response language
    
    # Aliases for frontend compatibility
    @property
    def heuristics(self) -> List[dict]:
        """Convert reasons to heuristics format for frontend."""
        return [{"name": r.split(":")[0] if ":" in r else "Finding", 
                 "score": 10, 
                 "description": r} for r in self.reasons]


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

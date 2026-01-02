"""
Community Threat Report Router for ThreatScan.

Allows users to anonymously report suspicious URLs for awareness
and view recent community-submitted threats.

Features:
- Anonymous URL submission (no IP/personal data stored)
- URL masking for safety (google.com -> google[.]com)
- Attack pattern analysis without visiting URLs
- Rate limiting to prevent abuse
- Multilingual educational explanations
"""

import re
import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.utils.threat_explainer import analyze_url_threats, TRANSLATIONS


router = APIRouter(prefix="/community", tags=["Community"])


# ========================
# Rate Limiting (Simple in-memory)
# ========================

# Track submissions by IP hash (we don't store actual IPs)
_rate_limit_store: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 5  # max submissions per window


def _get_client_hash(request: Request) -> str:
    """
    Generate a hash identifier for rate limiting.
    We don't store the actual IP for privacy.
    """
    client_ip = request.client.host if request.client else "unknown"
    # Simple hash - not storing actual IP
    return str(hash(client_ip) % 1000000)


def _check_rate_limit(client_hash: str) -> bool:
    """
    Check if client is within rate limits.
    Returns True if allowed, False if rate limited.
    """
    current_time = time.time()
    
    # Clean old entries
    _rate_limit_store[client_hash] = [
        t for t in _rate_limit_store[client_hash]
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    
    # Check limit
    if len(_rate_limit_store[client_hash]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    # Record this request
    _rate_limit_store[client_hash].append(current_time)
    return True


# ========================
# URL Masking Utility
# ========================

def mask_url(url: str) -> str:
    """
    Mask a URL to prevent accidental clicks.
    Replaces dots with [.] to make URLs non-clickable.
    
    Example: google.com.com -> google[.]com[.]com
    """
    # Remove protocol for cleaner display
    masked = re.sub(r'^https?://', '', url)
    # Replace dots with [.]
    masked = masked.replace('.', '[.]')
    return masked


def unmask_url(masked_url: str) -> str:
    """Reverse the masking for internal analysis."""
    return masked_url.replace('[.]', '.')


# ========================
# Schemas
# ========================

class CommunityReportCreate(BaseModel):
    """Schema for submitting a community threat report."""
    url_text: str = Field(..., min_length=3, max_length=2000, description="The suspicious URL text")
    threat_category: str = Field(..., description="Category: phishing, scam, fake_login, unknown")
    optional_description: Optional[str] = Field(None, max_length=500, description="Optional user description")
    language: str = Field("en", description="Language for explanations: en, hi, mr")
    
    def validate_category(self) -> str:
        """Validate and normalize the threat category."""
        valid_categories = ["phishing", "scam", "fake_login", "unknown"]
        cat = self.threat_category.lower().replace(" ", "_")
        return cat if cat in valid_categories else "unknown"


class CommunityReportOut(BaseModel):
    """Schema for community report response."""
    id: str
    masked_url: str
    threat_category: str
    attack_patterns: List[str]
    explanation: str
    safety_tip: str
    submitted_at: str
    language: str


# ========================
# In-Memory Storage
# ========================
# In production, this would be a database table

_community_reports: List[Dict] = []
_report_counter = 0


def _store_report(report_data: Dict) -> str:
    """Store a community report and return its ID."""
    global _report_counter
    _report_counter += 1
    report_id = f"CR-{_report_counter:06d}"
    report_data["id"] = report_id
    report_data["submitted_at"] = datetime.utcnow().isoformat()
    _community_reports.append(report_data)
    
    # Keep only last 100 reports in memory
    if len(_community_reports) > 100:
        _community_reports.pop(0)
    
    return report_id


# ========================
# Multilingual Support
# ========================

CATEGORY_TRANSLATIONS = {
    "en": {
        "phishing": "Phishing Attack",
        "scam": "Scam/Fraud",
        "fake_login": "Fake Login Page",
        "unknown": "Unknown Threat",
    },
    "hi": {
        "phishing": "फ़िशिंग हमला",
        "scam": "धोखाधड़ी",
        "fake_login": "नकली लॉगिन पेज",
        "unknown": "अज्ञात खतरा",
    },
    "mr": {
        "phishing": "फिशिंग हल्ला",
        "scam": "फसवणूक",
        "fake_login": "बनावट लॉगिन पेज",
        "unknown": "अज्ञात धोका",
    }
}

EDUCATIONAL_MESSAGES = {
    "en": {
        "warning": "⚠️ Do not click shared links. This is for awareness only.",
        "no_patterns": "No obvious attack patterns detected, but always verify URLs before clicking.",
    },
    "hi": {
        "warning": "⚠️ साझा किए गए लिंक पर क्लिक न करें। यह केवल जागरूकता के लिए है।",
        "no_patterns": "कोई स्पष्ट हमले का पैटर्न नहीं मिला, लेकिन हमेशा क्लिक करने से पहले URL सत्यापित करें।",
    },
    "mr": {
        "warning": "⚠️ शेअर केलेल्या लिंकवर क्लिक करू नका. हे फक्त जागरूकतेसाठी आहे.",
        "no_patterns": "कोणतेही स्पष्ट हल्ला पॅटर्न आढळले नाहीत, परंतु नेहमी क्लिक करण्यापूर्वी URLs सत्यापित करा.",
    }
}


# ========================
# API Endpoints
# ========================

@router.post("/report", response_model=CommunityReportOut)
async def submit_community_report(
    report: CommunityReportCreate,
    request: Request
):
    """
    Submit a suspicious URL for community awareness.
    
    - URL is analyzed for attack patterns WITHOUT visiting it
    - URL is masked before storage to prevent accidental clicks
    - No personal data is stored (anonymous submission)
    - Rate limited to prevent abuse
    """
    # Check rate limit
    client_hash = _get_client_hash(request)
    if not _check_rate_limit(client_hash):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait before submitting again."
        )
    
    # Validate language
    lang = report.language if report.language in ["en", "hi", "mr"] else "en"
    
    # Clean and analyze URL (without visiting it)
    url_text = report.url_text.strip()
    
    # Add protocol if missing (for parsing)
    analysis_url = url_text
    if not analysis_url.startswith(("http://", "https://")):
        analysis_url = f"http://{url_text}"
    
    # Analyze URL structure for attack patterns
    threat_analysis = analyze_url_threats(analysis_url, lang)
    
    # Mask the URL for safe display
    masked_url = mask_url(url_text)
    
    # Get category in user's language
    category = report.validate_category()
    category_display = CATEGORY_TRANSLATIONS.get(lang, CATEGORY_TRANSLATIONS["en"]).get(
        category, category
    )
    
    # Generate explanation
    attack_patterns = threat_analysis.get("attack_patterns", [])
    reasons = threat_analysis.get("reasons", [])
    
    if reasons:
        explanation = " ".join(reasons[:2])  # Limit to first 2 reasons
    else:
        explanation = EDUCATIONAL_MESSAGES.get(lang, EDUCATIONAL_MESSAGES["en"])["no_patterns"]
    
    # Get safety tip from threat analysis or use default
    safety_tip = TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(
        "tip_general", 
        "When in doubt, go directly to the official website by typing the address yourself."
    )
    
    # Store the report (anonymously)
    report_data = {
        "masked_url": masked_url,
        "threat_category": category,
        "threat_category_display": category_display,
        "attack_patterns": attack_patterns,
        "explanation": explanation,
        "safety_tip": safety_tip,
        "language": lang,
        # Note: We don't store user_description to avoid potential PII
    }
    
    report_id = _store_report(report_data)
    
    return CommunityReportOut(
        id=report_id,
        masked_url=masked_url,
        threat_category=category_display,
        attack_patterns=attack_patterns,
        explanation=explanation,
        safety_tip=safety_tip,
        submitted_at=report_data["submitted_at"],
        language=lang
    )


@router.get("/reports", response_model=List[CommunityReportOut])
async def get_community_reports(
    language: str = "en",
    limit: int = 20
):
    """
    Get recent community-submitted threat reports.
    
    Returns educational information about reported URLs:
    - Masked URLs (safe, non-clickable format)
    - Detected attack patterns
    - Educational explanations
    
    ⚠️ Warning: Do not attempt to visit these URLs.
    """
    # Validate language
    lang = language if language in ["en", "hi", "mr"] else "en"
    
    # Limit results
    limit = min(max(1, limit), 50)  # Between 1 and 50
    
    # Get recent reports
    recent_reports = _community_reports[-limit:][::-1]  # Newest first
    
    # Format response
    result = []
    for report in recent_reports:
        # Translate category if language differs
        if report.get("language") != lang:
            category = report.get("threat_category", "unknown")
            category_display = CATEGORY_TRANSLATIONS.get(lang, CATEGORY_TRANSLATIONS["en"]).get(
                category, category
            )
        else:
            category_display = report.get("threat_category_display", report.get("threat_category"))
        
        result.append(CommunityReportOut(
            id=report["id"],
            masked_url=report["masked_url"],
            threat_category=category_display,
            attack_patterns=report.get("attack_patterns", []),
            explanation=report.get("explanation", ""),
            safety_tip=report.get("safety_tip", ""),
            submitted_at=report.get("submitted_at", ""),
            language=report.get("language", "en")
        ))
    
    return result


@router.get("/warning")
async def get_warning_message(language: str = "en"):
    """
    Get the safety warning message in the specified language.
    """
    lang = language if language in ["en", "hi", "mr"] else "en"
    return {
        "warning": EDUCATIONAL_MESSAGES.get(lang, EDUCATIONAL_MESSAGES["en"])["warning"],
        "language": lang
    }

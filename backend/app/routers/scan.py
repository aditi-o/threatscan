"""
Scan router for SafeLink Shield.
Handles URL, text, screenshot, and audio scanning.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.schemas import ScanRequest, ScanResponse, AudioScanResponse, ScreenshotScanResponse
from app.crud import create_scan
from app.routers.auth import get_optional_user
from app.utils.hf_client import hf_client
from app.utils.heuristics import analyze_url_structure, analyze_text_content, compute_composite_score
from app.utils.ocr import image_to_text
from app.utils.stt import audio_to_text, is_supported_audio_format
from app.utils.sanitizers import redact_pii

router = APIRouter(prefix="/scan", tags=["Scanning"])

# Scam category labels for zero-shot classification
SCAM_LABELS = [
    "digital arrest scam",
    "UPI payment scam",
    "refund scam",
    "job offer scam",
    "romance scam",
    "lottery or prize scam",
    "tech support scam",
    "safe legitimate message"
]

# Model version for tracking
MODEL_VERSION = "v1.0-hf"


def get_safety_suggestions(label: str, risk_score: int) -> List[str]:
    """Generate safety suggestions based on scam type."""
    base_suggestions = [
        "Do not share OTP, PIN, or passwords with anyone",
        "Verify the sender through official channels",
        "Report suspicious messages to cyber crime helpline"
    ]
    
    specific = {
        "digital arrest": [
            "Police/CBI never demand money over phone",
            "Do not make any video calls with strangers claiming authority"
        ],
        "UPI": [
            "Never scan QR codes to receive money",
            "Do not enter UPI PIN for receiving payments"
        ],
        "refund": [
            "Genuine refunds don't require you to pay first",
            "Contact the company directly through their official website"
        ],
        "job": [
            "Legitimate jobs don't require upfront fees",
            "Research the company before sharing personal details"
        ],
        "romance": [
            "Never send money to someone you've only met online",
            "Be wary of profiles that seem too good to be true"
        ],
        "lottery": [
            "You cannot win a lottery you didn't enter",
            "Legitimate prizes don't require advance payments"
        ]
    }
    
    # Add specific suggestions based on label
    for key, suggestions in specific.items():
        if key.lower() in label.lower():
            return suggestions + base_suggestions[:2]
    
    return base_suggestions


@router.post("/url", response_model=ScanResponse)
async def scan_url(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Scan a URL for potential threats.
    
    Uses URLBert model + heuristic analysis for comprehensive detection.
    """
    # Get URL from request (supports both 'content' and 'url' fields)
    url = request.get_content().strip()
    
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Validate URL format
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Run heuristic analysis
    heuristic_result = analyze_url_structure(url)
    
    # Run ML classification
    ml_result = await hf_client.classify_url(url)
    
    # Calculate model probability
    model_prob = 0.0
    if ml_result:
        # Handle nested list response from HF router API: [[{...}]] or [{...}]
        result_list = ml_result
        if isinstance(ml_result, list) and len(ml_result) > 0:
            # Check if it's a nested list (new HF router format)
            if isinstance(ml_result[0], list):
                result_list = ml_result[0]
            
            for item in result_list:
                if isinstance(item, dict) and item.get("label") == "malicious":
                    model_prob = item.get("score", 0)
                    break
    
    # Compute composite risk score
    risk_score = compute_composite_score(model_prob, heuristic_result["score"])
    
    # Determine label and safety
    is_safe = risk_score < 30
    if risk_score >= 70:
        label = "High Risk - Likely Malicious"
    elif risk_score >= 40:
        label = "Medium Risk - Suspicious"
    else:
        label = "Low Risk - Appears Safe"
    
    # Build response
    result = ScanResponse(
        input_type="url",
        input_text=url,
        risk_score=risk_score,
        label=label,
        is_safe=is_safe,
        reasons=heuristic_result["flags"] if heuristic_result["flags"] else ["No suspicious patterns detected"],
        suggestions=get_safety_suggestions(label, risk_score),
        model_version=MODEL_VERSION
    )
    
    # Save to database
    user_id = current_user.id if current_user else None
    try:
        db_scan = await create_scan(
            db,
            user_id=user_id,
            input_type="url",
            input_text=url,
            result_json=result.model_dump(),
            model_version=MODEL_VERSION
        )
        result.scan_id = db_scan.id
    except Exception as e:
        print(f"Warning: Could not save scan to database: {e}")
    
    return result


@router.post("/text", response_model=ScanResponse)
async def scan_text(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Scan text message for scam patterns.
    
    Uses zero-shot classification to identify scam types.
    """
    # Get text from request (supports both 'content' and 'text' fields)
    text = request.get_content().strip()
    
    if not text:
        raise HTTPException(status_code=400, detail="Text content is required")
    
    if len(text) < 10:
        raise HTTPException(status_code=400, detail="Text too short for analysis")
    
    # Redact PII for storage
    redacted_text, _ = redact_pii(text)
    
    # Run heuristic analysis
    heuristic_result = analyze_text_content(text)
    
    # Run zero-shot classification
    ml_result = await hf_client.classify_text_zero_shot(text, SCAM_LABELS)
    
    # Extract best matching label and score
    model_prob = 0.0
    label = "Unknown"
    
    if ml_result and "labels" in ml_result and "scores" in ml_result:
        labels = ml_result["labels"]
        scores = ml_result["scores"]
        
        # Get highest scoring label
        max_idx = scores.index(max(scores))
        label = labels[max_idx]
        
        # If the top label is "safe", invert the probability
        if "safe" in label.lower():
            model_prob = 1 - scores[max_idx]
            label = labels[1] if len(labels) > 1 else "Unknown"
        else:
            model_prob = scores[max_idx]
    
    # Compute composite risk score
    risk_score = compute_composite_score(model_prob, heuristic_result["score"])
    
    # Determine safety
    is_safe = risk_score < 30
    
    # Combine reasons
    reasons = heuristic_result["flags"].copy()
    if model_prob > 0.3:
        reasons.insert(0, f"ML model detected: {label} ({int(model_prob * 100)}% confidence)")
    
    if not reasons:
        reasons = ["No suspicious patterns detected"]
    
    result = ScanResponse(
        input_type="text",
        input_text=redacted_text,
        risk_score=risk_score,
        label=label.title(),
        is_safe=is_safe,
        reasons=reasons,
        suggestions=get_safety_suggestions(label, risk_score),
        model_version=MODEL_VERSION
    )
    
    # Save to database
    user_id = current_user.id if current_user else None
    try:
        db_scan = await create_scan(
            db,
            user_id=user_id,
            input_type="text",
            input_text=redacted_text,
            result_json=result.model_dump(),
            model_version=MODEL_VERSION
        )
        result.scan_id = db_scan.id
    except Exception as e:
        print(f"Warning: Could not save scan to database: {e}")
    
    return result


@router.post("/screenshot", response_model=ScreenshotScanResponse)
async def scan_screenshot(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Scan a screenshot for scam content.
    
    Extracts text using OCR, then analyzes for scam patterns.
    """
    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Read file
    file_bytes = await file.read()
    
    if len(file_bytes) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    
    # Extract text using OCR
    extracted_text = image_to_text(file_bytes)
    
    if not extracted_text:
        raise HTTPException(
            status_code=422,
            detail="Could not extract text from image. Please try a clearer image or ensure Tesseract OCR is installed."
        )
    
    # Redact PII
    redacted_text, _ = redact_pii(extracted_text)
    
    # Run heuristic analysis
    heuristic_result = analyze_text_content(extracted_text)
    
    # Run zero-shot classification
    ml_result = await hf_client.classify_text_zero_shot(extracted_text, SCAM_LABELS)
    
    # Process ML result
    model_prob = 0.0
    label = "Unknown"
    
    if ml_result and "labels" in ml_result and "scores" in ml_result:
        labels = ml_result["labels"]
        scores = ml_result["scores"]
        max_idx = scores.index(max(scores))
        label = labels[max_idx]
        
        if "safe" in label.lower():
            model_prob = 1 - scores[max_idx]
            label = labels[1] if len(labels) > 1 else "Unknown"
        else:
            model_prob = scores[max_idx]
    
    # Compute risk score
    risk_score = compute_composite_score(model_prob, heuristic_result["score"])
    is_safe = risk_score < 30
    
    # Build reasons
    reasons = heuristic_result["flags"].copy()
    if model_prob > 0.3:
        reasons.insert(0, f"Detected: {label} ({int(model_prob * 100)}% confidence)")
    if not reasons:
        reasons = ["No suspicious patterns detected in extracted text"]
    
    result = ScreenshotScanResponse(
        input_type="screenshot",
        input_text=redacted_text[:500],
        extracted_text=redacted_text,
        risk_score=risk_score,
        label=label.title(),
        is_safe=is_safe,
        reasons=reasons,
        suggestions=get_safety_suggestions(label, risk_score),
        model_version=MODEL_VERSION
    )
    
    # Save to database
    user_id = current_user.id if current_user else None
    try:
        db_scan = await create_scan(
            db,
            user_id=user_id,
            input_type="screenshot",
            input_text=redacted_text[:1000],
            result_json=result.model_dump(),
            model_version=MODEL_VERSION
        )
        result.scan_id = db_scan.id
    except Exception as e:
        print(f"Warning: Could not save scan to database: {e}")
    
    return result


@router.post("/audio", response_model=AudioScanResponse)
async def scan_audio(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_optional_user)
):
    """
    Analyze an audio call for scam patterns.
    
    Transcribes audio using Whisper, then analyzes for scam patterns.
    """
    # Validate file format
    filename = file.filename or "audio.wav"
    if not is_supported_audio_format(filename):
        raise HTTPException(
            status_code=400,
            detail="Unsupported audio format. Supported: WAV, MP3, M4A, AAC, OGG, FLAC"
        )
    
    # Read file
    file_bytes = await file.read()
    
    if len(file_bytes) > 25 * 1024 * 1024:  # 25MB limit
        raise HTTPException(status_code=400, detail="File too large (max 25MB)")
    
    # Transcribe audio
    transcript = await audio_to_text(file_bytes, filename)
    
    if not transcript:
        raise HTTPException(
            status_code=422,
            detail="Could not transcribe audio. Please try a clearer recording or check HF API key."
        )
    
    # Redact PII
    redacted_transcript, _ = redact_pii(transcript)
    
    # Run heuristic analysis
    heuristic_result = analyze_text_content(transcript)
    
    # Run zero-shot classification
    ml_result = await hf_client.classify_text_zero_shot(transcript, SCAM_LABELS)
    
    # Process ML result
    model_prob = 0.0
    label = "Unknown"
    
    if ml_result and "labels" in ml_result and "scores" in ml_result:
        labels = ml_result["labels"]
        scores = ml_result["scores"]
        max_idx = scores.index(max(scores))
        label = labels[max_idx]
        
        if "safe" in label.lower():
            model_prob = 1 - scores[max_idx]
            label = labels[1] if len(labels) > 1 else "Unknown"
        else:
            model_prob = scores[max_idx]
    
    # Compute risk score
    risk_score = compute_composite_score(model_prob, heuristic_result["score"])
    is_safe = risk_score < 30
    
    # Build reasons
    reasons = heuristic_result["flags"].copy()
    if model_prob > 0.3:
        reasons.insert(0, f"Detected: {label} ({int(model_prob * 100)}% confidence)")
    if not reasons:
        reasons = ["No suspicious patterns detected in call transcript"]
    
    result = AudioScanResponse(
        input_type="audio",
        input_text=redacted_transcript[:500],
        transcript=redacted_transcript,
        risk_score=risk_score,
        label=label.title(),
        is_safe=is_safe,
        reasons=reasons,
        suggestions=get_safety_suggestions(label, risk_score),
        model_version=MODEL_VERSION
    )
    
    # Save to database
    user_id = current_user.id if current_user else None
    try:
        db_scan = await create_scan(
            db,
            user_id=user_id,
            input_type="audio",
            input_text=redacted_transcript[:1000],
            result_json=result.model_dump(),
            model_version=MODEL_VERSION
        )
        result.scan_id = db_scan.id
    except Exception as e:
        print(f"Warning: Could not save scan to database: {e}")
    
    return result

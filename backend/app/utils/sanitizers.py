"""
Data sanitization utilities.
Redacts PII (Personally Identifiable Information) before storage.
"""

import re
from typing import Tuple


def redact_pii(text: str) -> Tuple[str, int]:
    """
    Redact personally identifiable information from text.
    
    Redacts:
    - Phone numbers
    - Email addresses
    - Credit/debit card numbers
    - Aadhaar numbers (India)
    - PAN numbers (India)
    - OTP codes
    - Bank account numbers
    
    Args:
        text: Input text to sanitize
    
    Returns:
        Tuple of (redacted text, count of redactions)
    """
    redaction_count = 0
    result = text
    
    # Patterns and their replacements
    patterns = [
        # Phone numbers (10+ digits, may include country code)
        (r'\+?[\d\s\-\(\)]{10,15}', '[PHONE_REDACTED]'),
        
        # Email addresses
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]'),
        
        # Credit/Debit card numbers (16 digits, may have spaces/dashes)
        (r'\b(?:\d{4}[\s\-]?){3}\d{4}\b', '[CARD_REDACTED]'),
        
        # CVV (3-4 digits, when preceded by cvv/cvc)
        (r'(?:cvv|cvc)[:\s]*\d{3,4}\b', 'CVV: [REDACTED]'),
        
        # Aadhaar numbers (India) - 12 digits
        (r'\b\d{4}\s?\d{4}\s?\d{4}\b', '[AADHAAR_REDACTED]'),
        
        # PAN numbers (India) - AAAAA9999A format
        (r'\b[A-Z]{5}\d{4}[A-Z]\b', '[PAN_REDACTED]'),
        
        # OTP codes (4-8 digits, when preceded by otp/code/pin)
        (r'(?:otp|code|pin|verify)[:\s]*\d{4,8}\b', 'OTP: [REDACTED]'),
        
        # UPI IDs
        (r'[a-zA-Z0-9._-]+@[a-zA-Z]+', '[UPI_REDACTED]'),
        
        # Bank account numbers (9-18 digits)
        (r'\b(?:a/?c|account)[:\s#]*\d{9,18}\b', 'Account: [REDACTED]'),
        
        # IFSC codes (India)
        (r'\b[A-Z]{4}0[A-Z0-9]{6}\b', '[IFSC_REDACTED]'),
    ]
    
    for pattern, replacement in patterns:
        matches = re.findall(pattern, result, re.IGNORECASE)
        if matches:
            redaction_count += len(matches)
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    
    return result, redaction_count


def sanitize_for_logging(text: str, max_length: int = 500) -> str:
    """
    Sanitize text for safe logging.
    Truncates and redacts PII.
    
    Args:
        text: Input text
        max_length: Maximum length to log
    
    Returns:
        Safe string for logging
    """
    # First redact PII
    sanitized, _ = redact_pii(text)
    
    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [TRUNCATED]"
    
    return sanitized


def sanitize_url(url: str) -> str:
    """
    Sanitize URL by removing potentially sensitive query parameters.
    
    Args:
        url: Input URL
    
    Returns:
        Sanitized URL
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    sensitive_params = ['password', 'pwd', 'token', 'key', 'api_key', 'secret', 'auth']
    
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Remove sensitive parameters
        for param in sensitive_params:
            query_params.pop(param, None)
        
        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        sanitized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return sanitized
        
    except Exception:
        return url


def validate_input_length(text: str, max_length: int = 10000) -> bool:
    """
    Validate input text length.
    
    Args:
        text: Input text
        max_length: Maximum allowed length
    
    Returns:
        True if valid, False if too long
    """
    return len(text) <= max_length

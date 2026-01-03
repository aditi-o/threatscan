"""
Input validation utilities for SafeLink Shield.

Provides comprehensive validation for:
- URLs (format, safety)
- File uploads (size, type, filename)
- Text content (length, format)
"""

import re
from typing import Tuple, Optional, List
from urllib.parse import urlparse


# ========================
# Constants
# ========================

# Maximum allowed sizes
MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 10000
MAX_MESSAGE_LENGTH = 1000
MAX_FILENAME_LENGTH = 255
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_AUDIO_SIZE = 25 * 1024 * 1024  # 25MB

# Allowed MIME types
ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/bmp"
}

ALLOWED_AUDIO_TYPES = {
    "audio/wav", "audio/wave", "audio/x-wav",
    "audio/mp3", "audio/mpeg",
    "audio/m4a", "audio/x-m4a", "audio/mp4",
    "audio/aac",
    "audio/ogg", "audio/vorbis",
    "audio/flac",
    "audio/webm"
}

# Dangerous filename patterns
DANGEROUS_FILENAME_PATTERNS = [
    r'\.{2,}',           # Multiple dots (path traversal)
    r'[<>:"|?*]',        # Windows forbidden chars
    r'[\x00-\x1f]',      # Control characters
    r'^\.+$',            # Only dots
    r'^\s+|\s+$',        # Leading/trailing whitespace
]


# ========================
# URL Validation
# ========================

def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format and safety.
    
    Args:
        url: URL string to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url or not isinstance(url, str):
        return False, "URL is required"
    
    url = url.strip()
    
    # Check length
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length ({MAX_URL_LENGTH} chars)"
    
    # Check for null bytes or control characters
    if any(ord(c) < 32 for c in url):
        return False, "URL contains invalid characters"
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"
        
        # Only allow http/https
        if parsed.scheme.lower() not in ('http', 'https'):
            return False, "Only HTTP/HTTPS URLs are allowed"
        
        # Check for localhost/internal IPs in production
        hostname = parsed.netloc.lower()
        
        # Block javascript: and data: schemes
        if parsed.scheme.lower() in ('javascript', 'data', 'vbscript'):
            return False, "Potentially dangerous URL scheme"
        
        return True, None
        
    except Exception:
        return False, "Invalid URL format"


def sanitize_url_for_display(url: str) -> str:
    """
    Sanitize URL for safe display (remove credentials, etc.)
    """
    try:
        parsed = urlparse(url)
        # Remove username:password if present
        if parsed.username or parsed.password:
            netloc = parsed.hostname
            if parsed.port:
                netloc += f":{parsed.port}"
            from urllib.parse import urlunparse
            return urlunparse((
                parsed.scheme, netloc, parsed.path,
                parsed.params, parsed.query, parsed.fragment
            ))
        return url
    except Exception:
        return url


# ========================
# Text Validation
# ========================

def validate_text(text: str, min_length: int = 1, max_length: int = MAX_TEXT_LENGTH) -> Tuple[bool, Optional[str]]:
    """
    Validate text content.
    
    Args:
        text: Text to validate
        min_length: Minimum required length
        max_length: Maximum allowed length
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not text or not isinstance(text, str):
        return False, "Text content is required"
    
    text = text.strip()
    
    if len(text) < min_length:
        return False, f"Text must be at least {min_length} characters"
    
    if len(text) > max_length:
        return False, f"Text exceeds maximum length ({max_length} chars)"
    
    # Check for null bytes
    if '\x00' in text:
        return False, "Text contains invalid characters"
    
    return True, None


# ========================
# File Validation
# ========================

def validate_file_upload(
    filename: str,
    content_type: Optional[str],
    file_size: int,
    allowed_types: set,
    max_size: int
) -> Tuple[bool, Optional[str]]:
    """
    Validate file upload parameters.
    
    Args:
        filename: Original filename
        content_type: MIME type
        file_size: Size in bytes
        allowed_types: Set of allowed MIME types
        max_size: Maximum file size in bytes
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate filename
    is_valid, error = validate_filename(filename)
    if not is_valid:
        return False, error
    
    # Validate content type
    if not content_type:
        return False, "Content type is required"
    
    # Normalize content type (remove charset, etc.)
    base_type = content_type.split(';')[0].strip().lower()
    
    if base_type not in allowed_types:
        return False, f"File type '{base_type}' is not allowed"
    
    # Validate file size
    if file_size <= 0:
        return False, "File is empty"
    
    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        return False, f"File size exceeds maximum ({max_mb:.0f}MB)"
    
    return True, None


def validate_filename(filename: str) -> Tuple[bool, Optional[str]]:
    """
    Validate and sanitize filename.
    
    Args:
        filename: Original filename
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not filename or not isinstance(filename, str):
        return False, "Filename is required"
    
    if len(filename) > MAX_FILENAME_LENGTH:
        return False, "Filename too long"
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_FILENAME_PATTERNS:
        if re.search(pattern, filename):
            return False, "Filename contains invalid characters"
    
    # Check for path traversal attempts
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return False, "Invalid filename"
    
    return True, None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"
    
    # Remove path components
    filename = filename.replace('\\', '/').split('/')[-1]
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*\x00-\x1f]', '_', filename)
    
    # Remove leading dots (hidden files)
    filename = filename.lstrip('.')
    
    # Limit length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = MAX_FILENAME_LENGTH - len(ext) - 1
        filename = name[:max_name_len] + ('.' + ext if ext else '')
    
    return filename or "unnamed"


def validate_image_upload(
    filename: str,
    content_type: Optional[str],
    file_size: int
) -> Tuple[bool, Optional[str]]:
    """Validate image file upload."""
    return validate_file_upload(
        filename, content_type, file_size,
        ALLOWED_IMAGE_TYPES, MAX_IMAGE_SIZE
    )


def validate_audio_upload(
    filename: str,
    content_type: Optional[str],
    file_size: int
) -> Tuple[bool, Optional[str]]:
    """Validate audio file upload."""
    return validate_file_upload(
        filename, content_type, file_size,
        ALLOWED_AUDIO_TYPES, MAX_AUDIO_SIZE
    )


# ========================
# Language Validation
# ========================

SUPPORTED_LANGUAGES = {"en", "hi", "mr"}

def validate_language(lang: str) -> str:
    """
    Validate and normalize language code.
    
    Args:
        lang: Language code
    
    Returns:
        Valid language code (defaults to 'en')
    """
    if not lang or not isinstance(lang, str):
        return "en"
    
    lang = lang.strip().lower()[:5]
    
    return lang if lang in SUPPORTED_LANGUAGES else "en"


# ========================
# Category Validation  
# ========================

THREAT_CATEGORIES = {"phishing", "scam", "fake_login", "unknown"}

def validate_threat_category(category: str) -> str:
    """
    Validate and normalize threat category.
    
    Args:
        category: Category string
    
    Returns:
        Valid category (defaults to 'unknown')
    """
    if not category or not isinstance(category, str):
        return "unknown"
    
    cat = category.strip().lower().replace(" ", "_")
    
    return cat if cat in THREAT_CATEGORIES else "unknown"

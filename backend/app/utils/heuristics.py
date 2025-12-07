"""
Heuristic analysis for URL and text scanning.
Provides rule-based scoring to complement ML models.
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple

# Suspicious keywords commonly found in scam messages
SUSPICIOUS_KEYWORDS = [
    # Urgency
    "urgent", "immediately", "act now", "limited time", "expire",
    # Money/Prize
    "lottery", "winner", "prize", "jackpot", "million", "lakh", "crore",
    "free money", "cash prize", "reward",
    # Account/Security
    "verify your account", "suspended", "blocked", "unauthorized",
    "security alert", "confirm your identity", "update your details",
    # Payment
    "bank details", "credit card", "cvv", "pin", "otp", "upi",
    "transfer", "payment failed", "refund",
    # Job scams
    "work from home", "easy money", "part time job", "data entry",
    "typing job", "investment opportunity",
    # Digital arrest / Impersonation
    "police", "cbi", "cyber cell", "arrest warrant", "legal action",
    "court case", "aadhaar", "pan card",
    # Romance scams
    "dear friend", "lonely", "send me money", "western union",
    # Generic phishing
    "click here", "login now", "verify now", "confirm now"
]

# Known malicious TLDs (not exhaustive)
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often abused
    ".xyz", ".top", ".work", ".click", ".link"
]

# IP address pattern
IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def has_https(url: str) -> bool:
    """Check if URL uses HTTPS."""
    return url.lower().startswith("https://")


def contains_ip(url: str) -> bool:
    """Check if URL contains an IP address instead of domain."""
    return bool(IP_PATTERN.search(url))


def has_suspicious_tld(url: str) -> bool:
    """Check if URL has a suspicious TLD."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    except:
        return False


def count_suspicious_keywords(text: str) -> Tuple[int, List[str]]:
    """
    Count suspicious keywords in text.
    
    Returns:
        Tuple of (count, list of found keywords)
    """
    text_lower = text.lower()
    found = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            found.append(keyword)
    
    return len(found), found


def analyze_url_structure(url: str) -> Dict:
    """
    Analyze URL structure for suspicious patterns.
    
    Returns:
        Dict with analysis results and flags
    """
    flags = []
    score = 0.0
    
    try:
        parsed = urlparse(url)
        
        # Check HTTPS
        if not has_https(url):
            flags.append("Missing HTTPS - connection not secure")
            score += 0.15
        
        # Check for IP address
        if contains_ip(url):
            flags.append("Uses IP address instead of domain name")
            score += 0.25
        
        # Check suspicious TLD
        if has_suspicious_tld(url):
            flags.append("Uses suspicious top-level domain")
            score += 0.2
        
        # Check for excessive subdomains
        domain_parts = parsed.netloc.split(".")
        if len(domain_parts) > 4:
            flags.append("Excessive subdomains - possible domain spoofing")
            score += 0.15
        
        # Check URL length (very long URLs are suspicious)
        if len(url) > 100:
            flags.append("Unusually long URL")
            score += 0.1
        
        # Check for suspicious patterns in path
        path = parsed.path.lower()
        if any(x in path for x in ["login", "verify", "secure", "account", "update"]):
            flags.append("Contains authentication-related keywords in path")
            score += 0.1
        
        # Check for encoded characters (potential obfuscation)
        if "%" in url and url.count("%") > 3:
            flags.append("Excessive URL encoding - possible obfuscation")
            score += 0.1
            
    except Exception as e:
        flags.append(f"URL parsing error: {str(e)}")
        score += 0.3
    
    return {
        "score": min(score, 1.0),  # Cap at 1.0
        "flags": flags
    }


def analyze_text_content(text: str) -> Dict:
    """
    Analyze text content for scam indicators.
    
    Returns:
        Dict with analysis results and flags
    """
    flags = []
    score = 0.0
    
    # Count suspicious keywords
    keyword_count, found_keywords = count_suspicious_keywords(text)
    if keyword_count > 0:
        flags.append(f"Contains suspicious keywords: {', '.join(found_keywords[:5])}")
        score += min(keyword_count * 0.1, 0.5)  # Cap keyword contribution
    
    # Check for ALL CAPS (common in scam messages)
    words = text.split()
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    if len(caps_words) > 3:
        flags.append("Excessive use of ALL CAPS - creates false urgency")
        score += 0.15
    
    # Check for excessive punctuation
    if text.count("!") > 3 or text.count("?") > 5:
        flags.append("Excessive punctuation - creates false urgency")
        score += 0.1
    
    # Check for phone numbers (potential contact for scam)
    phone_pattern = re.compile(r"[\+]?[\d\s\-]{10,}")
    if phone_pattern.search(text):
        flags.append("Contains phone number - verify before calling")
        score += 0.05
    
    # Check for currency mentions
    currency_pattern = re.compile(r"[₹$€£]\s*[\d,]+|[\d,]+\s*(rs|inr|usd|dollars?)", re.I)
    if currency_pattern.search(text):
        flags.append("Mentions monetary amounts")
        score += 0.1
    
    # Check for links
    link_pattern = re.compile(r"https?://|www\.", re.I)
    if link_pattern.search(text):
        flags.append("Contains links - verify before clicking")
        score += 0.1
    
    return {
        "score": min(score, 1.0),
        "flags": flags
    }


def compute_composite_score(
    model_score: float,
    heuristic_score: float,
    weights: Dict[str, float] = None
) -> int:
    """
    Compute composite risk score from multiple signals.
    
    Args:
        model_score: ML model probability (0-1)
        heuristic_score: Heuristic analysis score (0-1)
        weights: Optional custom weights
    
    Returns:
        Risk score from 0-100
    """
    default_weights = {
        "model": 0.6,
        "heuristic": 0.4
    }
    weights = weights or default_weights
    
    composite = (
        model_score * weights["model"] +
        heuristic_score * weights["heuristic"]
    )
    
    return round(composite * 100)

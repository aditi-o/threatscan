"""
Tests for SafeLink Shield scan endpoints.
Run with: pytest tests/test_scan.py -v
"""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

# Note: For proper async testing, use pytest-asyncio
# These tests use sync TestClient for simplicity


@pytest.fixture
def mock_hf_client():
    """Mock HuggingFace client for testing."""
    with patch("app.utils.hf_client.hf_client") as mock:
        # Mock URL classification
        mock.classify_url = AsyncMock(return_value=[
            {"label": "safe", "score": 0.95},
            {"label": "malicious", "score": 0.05}
        ])
        
        # Mock text classification
        mock.classify_text_zero_shot = AsyncMock(return_value={
            "labels": ["safe legitimate message", "digital arrest scam"],
            "scores": [0.85, 0.15]
        })
        
        yield mock


class TestHeuristics:
    """Test heuristic analysis functions."""
    
    def test_has_https(self):
        from app.utils.heuristics import has_https
        
        assert has_https("https://example.com") is True
        assert has_https("http://example.com") is False
        assert has_https("HTTPS://EXAMPLE.COM") is True
    
    def test_contains_ip(self):
        from app.utils.heuristics import contains_ip
        
        assert contains_ip("http://192.168.1.1/login") is True
        assert contains_ip("https://example.com") is False
    
    def test_suspicious_keywords(self):
        from app.utils.heuristics import count_suspicious_keywords
        
        # Safe text
        count, keywords = count_suspicious_keywords("Hello, how are you?")
        assert count == 0
        
        # Suspicious text
        count, keywords = count_suspicious_keywords(
            "URGENT: Your account is suspended! Verify now!"
        )
        assert count >= 2
        assert "urgent" in keywords
        assert "verify" in [k for k in keywords if "verify" in k.lower()]
    
    def test_analyze_url_structure(self):
        from app.utils.heuristics import analyze_url_structure
        
        # Safe URL
        result = analyze_url_structure("https://www.google.com")
        assert result["score"] < 0.3
        
        # Suspicious URL with IP
        result = analyze_url_structure("http://192.168.1.1/login/verify")
        assert result["score"] > 0.3
        assert any("IP address" in flag for flag in result["flags"])


class TestSanitizers:
    """Test PII redaction functions."""
    
    def test_redact_phone(self):
        from app.utils.sanitizers import redact_pii
        
        text = "Call me at 9876543210"
        redacted, count = redact_pii(text)
        assert "[PHONE_REDACTED]" in redacted
        assert count >= 1
    
    def test_redact_email(self):
        from app.utils.sanitizers import redact_pii
        
        text = "Contact: test@example.com"
        redacted, count = redact_pii(text)
        assert "[EMAIL_REDACTED]" in redacted
    
    def test_redact_aadhaar(self):
        from app.utils.sanitizers import redact_pii
        
        text = "Aadhaar: 1234 5678 9012"
        redacted, count = redact_pii(text)
        assert "[AADHAAR_REDACTED]" in redacted
    
    def test_safe_text_unchanged(self):
        from app.utils.sanitizers import redact_pii
        
        text = "This is a safe message with no PII"
        redacted, count = redact_pii(text)
        assert text == redacted
        assert count == 0


class TestRiskScore:
    """Test risk score calculation."""
    
    def test_composite_score_low_risk(self):
        from app.utils.heuristics import compute_composite_score
        
        # Low model and heuristic scores
        score = compute_composite_score(0.1, 0.1)
        assert score < 30
    
    def test_composite_score_high_risk(self):
        from app.utils.heuristics import compute_composite_score
        
        # High model and heuristic scores
        score = compute_composite_score(0.9, 0.8)
        assert score > 70
    
    def test_composite_score_range(self):
        from app.utils.heuristics import compute_composite_score
        
        # Score should always be 0-100
        for m in [0, 0.5, 1.0]:
            for h in [0, 0.5, 1.0]:
                score = compute_composite_score(m, h)
                assert 0 <= score <= 100


# Integration tests (require running server)
class TestAuthFlow:
    """Test authentication endpoints."""
    
    def test_signup_login_flow(self):
        """
        Test user registration and login.
        Note: This requires a running server.
        For CI, use TestClient with dependency overrides.
        """
        # Placeholder - implement with TestClient
        pass


class TestScanEndpoints:
    """Test scan API endpoints."""
    
    def test_url_scan_validation(self):
        """Test URL validation in scan endpoint."""
        # Placeholder - implement with TestClient
        pass
    
    def test_text_scan_short_input(self):
        """Test that short text is rejected."""
        # Placeholder - implement with TestClient
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

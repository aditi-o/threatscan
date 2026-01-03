"""
Rate limiting middleware for SafeLink Shield.

Provides IP-based rate limiting to prevent abuse.
"""

import time
from typing import Dict, List, Optional, Callable
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitConfig:
    """Configuration for rate limiting."""
    
    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_limit: int = 10,
        burst_window: int = 10  # seconds
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_limit = burst_limit
        self.burst_window = burst_window


# Default configs for different endpoint types
RATE_LIMITS = {
    "scan": RateLimitConfig(
        requests_per_minute=20,  # 20 scans per minute
        requests_per_hour=200,   # 200 scans per hour
        burst_limit=5,           # 5 rapid scans
        burst_window=10
    ),
    "chat": RateLimitConfig(
        requests_per_minute=30,  # 30 messages per minute
        requests_per_hour=500,
        burst_limit=10,
        burst_window=10
    ),
    "community": RateLimitConfig(
        requests_per_minute=5,   # 5 reports per minute
        requests_per_hour=20,    # 20 reports per hour
        burst_limit=3,
        burst_window=60
    ),
    "auth": RateLimitConfig(
        requests_per_minute=10,  # 10 auth attempts per minute
        requests_per_hour=50,
        burst_limit=5,
        burst_window=60
    ),
    "default": RateLimitConfig(
        requests_per_minute=60,
        requests_per_hour=1000,
        burst_limit=20,
        burst_window=10
    )
}


class RateLimiter:
    """
    In-memory rate limiter.
    
    For production, consider using Redis for distributed rate limiting.
    """
    
    def __init__(self):
        # Store: {client_id: [(timestamp, endpoint_type), ...]}
        self._requests: Dict[str, List[tuple]] = defaultdict(list)
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
    
    def _get_client_id(self, request: Request) -> str:
        """
        Get client identifier for rate limiting.
        Uses IP address (hashed for privacy).
        """
        # Get real IP (handle proxies)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"
        
        # Hash for privacy (we don't need to store actual IPs)
        return str(hash(ip) % 10000000)
    
    def _get_endpoint_type(self, path: str) -> str:
        """Determine endpoint type from path for rate limit config."""
        if "/scan/" in path:
            return "scan"
        elif "/chat" in path:
            return "chat"
        elif "/community" in path:
            return "community"
        elif "/auth" in path:
            return "auth"
        return "default"
    
    def _cleanup_old_entries(self):
        """Remove old entries to prevent memory buildup."""
        current_time = time.time()
        
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        one_hour_ago = current_time - 3600
        
        for client_id in list(self._requests.keys()):
            self._requests[client_id] = [
                (ts, ep) for ts, ep in self._requests[client_id]
                if ts > one_hour_ago
            ]
            if not self._requests[client_id]:
                del self._requests[client_id]
        
        self._last_cleanup = current_time
    
    def check_rate_limit(self, request: Request) -> Optional[str]:
        """
        Check if request is within rate limits.
        
        Returns:
            None if allowed, error message if rate limited
        """
        self._cleanup_old_entries()
        
        client_id = self._get_client_id(request)
        endpoint_type = self._get_endpoint_type(request.url.path)
        config = RATE_LIMITS.get(endpoint_type, RATE_LIMITS["default"])
        
        current_time = time.time()
        one_minute_ago = current_time - 60
        one_hour_ago = current_time - 3600
        burst_window_ago = current_time - config.burst_window
        
        # Get requests for this endpoint type
        client_requests = self._requests[client_id]
        relevant_requests = [
            (ts, ep) for ts, ep in client_requests
            if ep == endpoint_type and ts > one_hour_ago
        ]
        
        # Check burst limit
        burst_count = sum(1 for ts, _ in relevant_requests if ts > burst_window_ago)
        if burst_count >= config.burst_limit:
            return f"Too many requests. Please wait {config.burst_window} seconds."
        
        # Check per-minute limit
        minute_count = sum(1 for ts, _ in relevant_requests if ts > one_minute_ago)
        if minute_count >= config.requests_per_minute:
            return "Rate limit exceeded. Please wait a minute before trying again."
        
        # Check per-hour limit
        if len(relevant_requests) >= config.requests_per_hour:
            return "Hourly rate limit exceeded. Please try again later."
        
        # Record this request
        self._requests[client_id].append((current_time, endpoint_type))
        
        return None


# Global rate limiter instance
rate_limiter = RateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to apply rate limiting to all requests.
    """
    
    # Paths to exclude from rate limiting
    EXCLUDED_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}
    
    async def dispatch(self, request: Request, call_next: Callable):
        # Skip rate limiting for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)
        
        # Skip for OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Check rate limit
        error = rate_limiter.check_rate_limit(request)
        if error:
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": {
                        "type": "rate_limit_exceeded",
                        "message": error,
                        "status_code": 429
                    }
                },
                headers={"Retry-After": "60"}
            )
        
        return await call_next(request)

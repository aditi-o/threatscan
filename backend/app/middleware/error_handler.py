"""
Global error handling middleware for SafeLink Shield.

Provides consistent error responses and prevents
exposure of internal details.
"""

import traceback
from typing import Callable
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class ErrorResponse:
    """Standard error response format."""
    
    @staticmethod
    def create(
        status_code: int,
        message: str,
        error_type: str = "error",
        details: str = None
    ) -> dict:
        """Create standardized error response."""
        response = {
            "success": False,
            "error": {
                "type": error_type,
                "message": message,
                "status_code": status_code
            }
        }
        if details:
            response["error"]["details"] = details
        return response


class GlobalErrorHandler(BaseHTTPMiddleware):
    """
    Middleware to catch and handle all exceptions consistently.
    
    - Converts all exceptions to JSON responses
    - Hides internal error details in production
    - Logs errors for debugging
    """
    
    def __init__(self, app, debug: bool = False):
        super().__init__(app)
        self.debug = debug
    
    async def dispatch(self, request: Request, call_next: Callable):
        try:
            response = await call_next(request)
            return response
            
        except HTTPException as exc:
            # FastAPI HTTP exceptions - pass through
            return JSONResponse(
                status_code=exc.status_code,
                content=ErrorResponse.create(
                    status_code=exc.status_code,
                    message=str(exc.detail),
                    error_type="http_error"
                )
            )
            
        except ValueError as exc:
            # Validation errors
            return JSONResponse(
                status_code=400,
                content=ErrorResponse.create(
                    status_code=400,
                    message=str(exc),
                    error_type="validation_error"
                )
            )
            
        except Exception as exc:
            # Log the full error for debugging
            print(f"❌ Unhandled error: {type(exc).__name__}: {str(exc)}")
            if self.debug:
                traceback.print_exc()
            
            # Return generic error (don't expose internals)
            error_message = "An unexpected error occurred"
            details = None
            
            if self.debug:
                error_message = str(exc)
                details = traceback.format_exc()
            
            return JSONResponse(
                status_code=500,
                content=ErrorResponse.create(
                    status_code=500,
                    message=error_message,
                    error_type="internal_error",
                    details=details
                )
            )


# Error response helpers for routes
def bad_request(message: str) -> HTTPException:
    """Create 400 Bad Request error."""
    return HTTPException(status_code=400, detail=message)


def unauthorized(message: str = "Authentication required") -> HTTPException:
    """Create 401 Unauthorized error."""
    return HTTPException(status_code=401, detail=message)


def forbidden(message: str = "Access denied") -> HTTPException:
    """Create 403 Forbidden error."""
    return HTTPException(status_code=403, detail=message)


def not_found(message: str = "Resource not found") -> HTTPException:
    """Create 404 Not Found error."""
    return HTTPException(status_code=404, detail=message)


def rate_limited(message: str = "Rate limit exceeded. Please wait before trying again.") -> HTTPException:
    """Create 429 Too Many Requests error."""
    return HTTPException(status_code=429, detail=message)


def unprocessable(message: str) -> HTTPException:
    """Create 422 Unprocessable Entity error."""
    return HTTPException(status_code=422, detail=message)


def internal_error(message: str = "An unexpected error occurred") -> HTTPException:
    """Create 500 Internal Server Error."""
    return HTTPException(status_code=500, detail=message)

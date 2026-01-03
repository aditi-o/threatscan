"""
SafeLink Shield - FastAPI Backend
Main application entry point.

Run with: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db import create_db
from app.routers import auth, scan, chat, report, admin, feedback, community
from app.middleware.error_handler import GlobalErrorHandler
from app.middleware.rate_limiter import RateLimitMiddleware


# ========================
# CORS Configuration
# ========================

# Production: Set ALLOWED_ORIGINS env var to comma-separated list
# e.g., "https://your-frontend.com,https://www.your-frontend.com"
ALLOWED_ORIGINS_ENV = os.getenv("ALLOWED_ORIGINS", "")

if ALLOWED_ORIGINS_ENV:
    # Production: Use configured origins
    ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_ENV.split(",") if origin.strip()]
else:
    # Development: Allow common local origins
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ]

# Check if running in development mode
IS_DEVELOPMENT = os.getenv("ENVIRONMENT", "development").lower() == "development"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events.
    Runs on startup and shutdown.
    """
    # Startup
    print("🚀 Starting SafeLink Shield Backend...")
    
    # Validate configuration
    warnings = settings.validate()
    for warning in warnings:
        print(f"⚠️  {warning}")
    
    # Log CORS configuration
    if IS_DEVELOPMENT:
        print("🔧 Running in DEVELOPMENT mode - CORS is relaxed")
    else:
        print(f"🔒 Running in PRODUCTION mode - CORS origins: {ALLOWED_ORIGINS[:3]}...")
    
    # Create database tables
    await create_db()
    
    print(f"✅ SafeLink Shield v{settings.API_VERSION} ready!")
    print("📖 API docs available at: http://localhost:8000/docs")
    
    yield
    
    # Shutdown
    print("👋 Shutting down SafeLink Shield...")


# Create FastAPI application
app = FastAPI(
    title="SafeLink Shield API",
    description="""
    SafeLink Shield is a comprehensive anti-scam protection platform.
    
    ## Features
    - 🔗 URL Scanning - Detect malicious links
    - 📝 Text Scanning - Identify scam messages
    - 📸 Screenshot OCR - Extract and analyze image text
    - 🎙️ Audio Analysis - Transcribe and scan call recordings
    - 🤖 AI Chatbot - Get scam protection advice
    - 📊 Reporting - Report suspicious content
    
    ## Authentication
    Protected endpoints require a Bearer token obtained from `/auth/login`.
    """,
    version=settings.API_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if IS_DEVELOPMENT else None,  # Disable docs in production
    redoc_url="/redoc" if IS_DEVELOPMENT else None
)

# Add global error handler FIRST (catches all errors)
app.add_middleware(GlobalErrorHandler, debug=IS_DEVELOPMENT)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Add CORS middleware with secure configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if not IS_DEVELOPMENT else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
    expose_headers=["X-Request-ID"],
    max_age=600,  # Cache preflight for 10 minutes
)

# Add GZip compression for responses
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Include routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(chat.router)
app.include_router(report.router)
app.include_router(admin.router)
app.include_router(feedback.router)
app.include_router(community.router)


@app.get("/", tags=["Health"])
async def root():
    """
    Health check endpoint.
    Returns API status and version.
    """
    return {
        "status": "ok",
        "name": "SafeLink Shield API",
        "version": settings.API_VERSION,
        "docs": "/docs" if IS_DEVELOPMENT else None
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Detailed health check.
    Useful for monitoring and load balancers.
    """
    return {
        "status": "healthy",
        "version": settings.API_VERSION,
        "hf_configured": bool(settings.HF_API_KEY),
        "openai_configured": bool(settings.OPENAI_API_KEY)
    }

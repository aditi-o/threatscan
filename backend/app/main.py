"""
SafeLink Shield - FastAPI Backend
Main application entry point.

Run with: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config import settings
from app.db import create_db
from app.routers import auth, scan, chat, report, admin, feedback, community


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
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware - Allow all origins for development
# In production, restrict to specific domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
        "docs": "/docs"
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

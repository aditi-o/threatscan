"""
Configuration module for SafeLink Shield backend.
Loads environment variables and provides settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application settings loaded from environment variables."""
    
    # Hugging Face API Key (required for ML models)
    HF_API_KEY: str = os.getenv("HF_API_KEY", "")
    
    # OpenAI API Key (optional, for chatbot)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    
    # Database URL (SQLite by default)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./safelink.db")
    
    # JWT Settings for authentication
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    
    # API Settings
    API_VERSION: str = "0.1.0"
    
    def validate(self):
        """Check if critical settings are configured."""
        warnings = []
        if not self.HF_API_KEY:
            warnings.append("HF_API_KEY not set - ML features will be limited")
        if not self.OPENAI_API_KEY:
            warnings.append("OPENAI_API_KEY not set - chatbot will use HuggingFace fallback")
        return warnings

# Global settings instance
settings = Settings()

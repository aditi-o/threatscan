"""
SQLAlchemy models for SafeLink Shield database.
Defines User, ScanHistory, and Report tables.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db import Base


class User(Base):
    """
    User model for authentication.
    Stores user credentials and profile info.
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scans = relationship("ScanHistory", back_populates="user")
    reports = relationship("Report", back_populates="user")


class ScanHistory(Base):
    """
    Scan history model.
    Stores all scans performed (URL, text, screenshot, audio).
    """
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Nullable for anonymous scans
    input_type = Column(String(20), nullable=False)  # url, text, screenshot, audio
    input_text = Column(Text, nullable=False)  # The URL, text, transcript, or extracted text
    result_json = Column(JSON, nullable=False)  # Full scan result as JSON
    model_version = Column(String(50), default="v1.0")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scans")


class Report(Base):
    """
    User-submitted scam reports.
    Allows users to report suspicious content.
    """
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    input_type = Column(String(20), nullable=False)  # url, text, screenshot, audio
    input_text = Column(Text, nullable=False)
    comment = Column(Text, nullable=True)  # User's description of why it's suspicious
    status = Column(String(20), default="pending")  # pending, reviewed, confirmed, rejected
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="reports")

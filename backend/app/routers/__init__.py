"""
Routers package for SafeLink Shield API.
Exports all API routers.
"""

from app.routers import auth, scan, chat, report, admin, feedback, community

__all__ = ["auth", "scan", "chat", "report", "admin", "feedback", "community"]

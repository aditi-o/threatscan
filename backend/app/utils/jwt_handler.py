"""
JWT token handling for authentication.
Creates and verifies JWT access tokens.
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from app.config import settings
from app.schemas import TokenData


def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary of claims to encode in the token
        expires_minutes: Token expiration time in minutes (uses default if None)
    
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    
    # Set expiration time
    expire_minutes = expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.utcnow() + timedelta(minutes=expire_minutes)
    to_encode.update({"exp": expire})
    
    # Encode the token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def verify_token(token: str) -> Optional[TokenData]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        TokenData if valid, None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        email: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if email is None:
            return None
            
        return TokenData(email=email, user_id=user_id)
    except JWTError:
        return None


def get_token_from_header(authorization: str) -> Optional[str]:
    """
    Extract token from Authorization header.
    
    Args:
        authorization: Authorization header value (e.g., "Bearer <token>")
    
    Returns:
        Token string if valid format, None otherwise
    """
    if not authorization:
        return None
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    
    return parts[1]

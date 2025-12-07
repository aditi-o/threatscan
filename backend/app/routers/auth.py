"""
Authentication router for SafeLink Shield.
Handles user registration, login, and token management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.schemas import UserCreate, UserOut, UserLogin, Token
from app.crud import create_user, get_user_by_email, verify_password, get_user_by_id
from app.utils.jwt_handler import create_access_token, verify_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Security scheme for protected endpoints
security = HTTPBearer()


@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account.
    
    - **name**: User's display name
    - **email**: Unique email address
    - **password**: Password (will be hashed)
    """
    # Check if email already exists
    existing_user = await get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create the user
    db_user = await create_user(db, user)
    return db_user


@router.post("/login", response_model=Token)
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    
    - **email**: Registered email address
    - **password**: User's password
    """
    # Find user by email
    db_user = await get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": db_user.email, "user_id": db_user.id}
    )
    
    return Token(access_token=access_token)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """
    Dependency to get the current authenticated user.
    Use with Depends() in protected endpoints.
    """
    token = credentials.credentials
    token_data = verify_token(token)
    
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    user = await get_user_by_id(db, token_data.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db)
):
    """
    Dependency to optionally get the current user.
    Returns None if not authenticated.
    """
    if credentials is None:
        return None
    
    token_data = verify_token(credentials.credentials)
    if token_data is None:
        return None
    
    return await get_user_by_id(db, token_data.user_id)


@router.get("/me", response_model=UserOut)
async def get_me(current_user = Depends(get_current_user)):
    """
    Get current user's profile information.
    Requires authentication.
    """
    return current_user

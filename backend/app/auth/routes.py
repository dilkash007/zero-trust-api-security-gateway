"""Authentication API endpoints: register, login, me, and protected test."""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.auth.jwt import create_access_token
from app.auth.schemas import (
    LoginRequest,
    LoginResponse,
    LoginUserData,
    ProtectedTestResponse,
    RegisterRequest,
    UserResponse,
)
from app.auth.security import hash_password, verify_password
from app.database.connection import get_db
from app.database.models import User, UserRole

logger = logging.getLogger("zero_trust.auth")

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
test_router = APIRouter(prefix="/api/test", tags=["Test & Verification"])


@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user identity",
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Registers a new standard user in the Zero-Trust identity system.

    - Checks for existing registered email (HTTP 409 if duplicate)
    - Hashes password using bcrypt (plaintext password is never stored or logged)
    - Role is strictly defaulted to USER (ADMIN cannot be self-selected)
    """
    normalized_email = payload.email.lower().strip()

    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        logger.warning("Registration rejected: Email %s is already registered", normalized_email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Hash the password safely
    hashed_pwd = hash_password(payload.password)

    new_user = User(
        name=payload.name,
        email=normalized_email,
        password_hash=hashed_pwd,
        role=UserRole.USER.value,
        is_active=True,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info("Successfully registered user id=%s email=%s with role=USER", new_user.id, new_user.email)
    return new_user


@auth_router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and receive JWT access token",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticates credentials and issues a signed JWT access token.

    Generic error is returned on failure without leaking email existence.
    """
    normalized_email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == normalized_email).first()

    # Generic credential rejection to prevent email enumeration
    if not user or not verify_password(payload.password, user.password_hash):
        logger.warning("Failed login attempt for email: %s", normalized_email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.warning("Login rejected: inactive account id=%s", user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    access_token = create_access_token(user_id=user.id, role=user.role)

    logger.info("Successful login for user id=%s role=%s", user.id, user.role)
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=LoginUserData.model_validate(user),
    )


@auth_router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve current authenticated user identity",
)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns the profile of the currently authenticated identity."""
    return current_user


@test_router.get(
    "/protected",
    response_model=ProtectedTestResponse,
    status_code=status.HTTP_200_OK,
    summary="Protected endpoint verification",
)
def protected_test_endpoint(current_user: User = Depends(get_current_user)):
    """Verifies that an authenticated request with a valid JWT can access protected routes."""
    return ProtectedTestResponse(
        message="Protected endpoint accessed successfully",
        user_id=current_user.id,
        role=current_user.role,
    )

"""Authentication dependencies for validating JWT tokens and injecting current user."""

import logging
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth.jwt import decode_access_token
from app.database.connection import get_db
from app.database.models import User

logger = logging.getLogger("zero_trust.auth")

# HTTP Bearer authentication scheme for OpenAPI integration
security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Dependency that extracts the Bearer token, validates it, and returns the active User.

    Raises:
        HTTPException 401: If token is missing, invalid, expired, or user not found.
        HTTPException 403: If user account is marked inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id_raw = payload.get("sub")
        if user_id_raw is None:
            logger.warning("Token validation failed: missing 'sub' claim")
            raise credentials_exception
        user_id = int(user_id_raw)
    except (JWTError, ValueError):
        logger.warning("Token validation failed: invalid signature or expired")
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning("Token validation failed: user ID %s not found", user_id)
        raise credentials_exception

    if not user.is_active:
        logger.warning("Access denied: user ID %s is inactive", user_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Optional user dependency: returns active User if valid token provided, else None."""
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
        user_id_raw = payload.get("sub")
        if user_id_raw is None:
            return None
        user = db.query(User).filter(User.id == int(user_id_raw)).first()
        return user if user and user.is_active else None
    except Exception:
        return None


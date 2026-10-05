"""JWT creation, signing, and decoding module using python-jose."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
from jose import JWTError, jwt
from app.config import settings


def create_access_token(
    user_id: Union[int, str],
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Creates a cryptographically signed JWT access token.

    Contains sub (user identifier), role, and expiration timestamp.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "role": str(role),
        "exp": expire,
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates the signature and expiration of a JWT access token.

    Raises:
        JWTError: If the token is invalid, forged, or expired.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )

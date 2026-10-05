"""Pydantic schemas for request validation and response serialization in auth."""

import re
from pydantic import BaseModel, ConfigDict, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class RegisterRequest(BaseModel):
    """Registration payload. Users cannot self-select ADMIN role."""
    name: str = Field(..., min_length=1, max_length=255, description="Full user name")
    email: str = Field(..., description="Valid corporate or user email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password with minimum 8 characters")

    @field_validator("name")
    @classmethod
    def validate_name_not_blank(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Name cannot be empty or whitespace only")
        return trimmed

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        cleaned = v.strip()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format")
        return cleaned


class LoginRequest(BaseModel):
    """User login credential payload."""
    email: str = Field(..., description="Registered user email")
    password: str = Field(..., min_length=1, description="Account password")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        cleaned = v.strip()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format")
        return cleaned


class UserResponse(BaseModel):
    """Public user identity response schema. Explicitly omits password and password_hash."""
    id: int
    name: str
    email: str
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class LoginUserData(BaseModel):
    """Embedded user metadata returned alongside JWT in login response."""
    id: int
    name: str
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class LoginResponse(BaseModel):
    """Login response returning JWT access token and user metadata."""
    access_token: str
    token_type: str = "bearer"
    user: LoginUserData


class ProtectedTestResponse(BaseModel):
    """Verification response for protected endpoints."""
    message: str = "Protected endpoint accessed successfully"
    user_id: int
    role: str

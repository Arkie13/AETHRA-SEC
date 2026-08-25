"""Request/response models."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from .validation import is_valid_email, is_valid_name


class RegisterRequest(BaseModel):
    name: str = Field(..., max_length=120)
    email: str = Field(..., max_length=254)
    #: Honeypot. A real visitor never sees or fills this field (hidden via
    #: CSS on the page); a non-empty value marks the submission as a bot.
    company: str = Field(default="", max_length=200)
    #: Client-reported epoch milliseconds of when the page loaded, used for
    #: the minimum-time-since-load bot check.
    loaded_at_ms: int = Field(default=0)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not is_valid_name(value):
            raise ValueError("Enter a name.")
        return value.strip()

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        if not is_valid_email(value):
            raise ValueError("Enter a valid email address.")
        return value.strip()


class RegisterResponse(BaseModel):
    count: int


class CountResponse(BaseModel):
    count: int


class AdminRegistrationOut(BaseModel):
    name: str
    email: str
    created_at: str

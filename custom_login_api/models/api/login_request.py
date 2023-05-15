from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError
from pydantic.errors import EmailError
from pydantic.networks import validate_email


class LoginRequest(BaseModel):
    """
    Model of the body of a login request.
    """

    email: str
    """Email address provided by the user requesting to log in."""
    password: str
    """Password provided by the user requesting to log in."""

    def __init__(self, **data: Any) -> None:
        """Constructor which performs a validation check on the email address provided."""
        try:
            validate_email(data.get("email", ""))
        except EmailError as e:
            raise ValidationError(errors=[], model=LoginRequest) from e
        super().__init__(**data)

    @classmethod
    def mock(cls) -> LoginRequest:
        """Example of a class object."""
        return LoginRequest(email="test@gmail.com", password="my-password")


class LoginRequestWithOtp(LoginRequest):
    """
    Model of the body of a login request, which also contains an OTP string.
    """

    otp: str
    """One-time password provided by the user requesting to log in."""

    @classmethod
    def mock(cls) -> LoginRequestWithOtp:
        """Example of a class object."""
        return LoginRequestWithOtp(email="test@gmail.com", password="my-password", otp="1234-5678")

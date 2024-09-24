from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic.networks import validate_email
from pydantic_core._pydantic_core import PydanticCustomError


class UserRegistrationData(BaseModel):
    """
    Model of the data provided by users to register to the platform.
    """

    email: str
    """The email address of the user."""
    password: str
    """The password provided by the user."""
    name: str
    """The first name of the user."""
    surname: str
    """The family name of the user."""
    enable_2fa: bool
    """Whether the user wishes to enable 2FA for logging in into the platform."""

    def __init__(self, **data: Any) -> None:
        """Constructor which performs validation checks on the values provided."""
        validate_email(data.get("email", ""))
        if not data.get("password", "") or not data.get("name", "") or not data.get("surname", ""):
            raise PydanticCustomError("", "")

        super().__init__(**data)

        # if not self.password or not self.name or not self.surname:
        #     raise ValidationError(errors=[], model=UserRegistrationData) from ValueError()

    @classmethod
    def mock(cls) -> UserRegistrationData:
        """Example of a class object."""
        return UserRegistrationData(
            email="test@gmail.com",
            password="my-password",
            name="Joe",
            surname="Walker",
            enable_2fa=True,
        )

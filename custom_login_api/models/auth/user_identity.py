from pydantic import BaseModel


class UserIdentity(BaseModel):
    """Model of the information about the user to whom the JWT was issued."""

    email: str
    """The user's email address."""

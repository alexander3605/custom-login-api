from datetime import datetime

from pydantic import BaseModel

from custom_login_api.models.auth.user_identity import UserIdentity


class TokenPayload(BaseModel):
    """
    Model of the payload of JWT tokens produced and used by the login service.
    """

    user_identity: UserIdentity
    """Information about the user to whom the JWT was issued."""
    exp: datetime
    """Expiration timestamp of the JWT."""

from pydantic import BaseModel


class SuccessfulLoginResponse(BaseModel):
    """
    Model of the response body returned by the login API endpoints to users that have successfully logged in.
    """

    token: str
    """String representation of the backend-produced JWT to be used by the user for issuing authenticated requests."""

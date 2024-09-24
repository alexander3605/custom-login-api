from datetime import datetime, timedelta

import jwt

from custom_login_api.models.auth.token_payload import TokenPayload
from custom_login_api.models.auth.user_identity import UserIdentity


class AuthenticationClient:
    """
    Client that exposes the functionalities needed to create and manage JWTs.
    """

    def __init__(self, jwt_secret_key: str, jwt_time_to_live: timedelta):
        self._jwt_secret_key = jwt_secret_key
        self._jwt_time_to_live = jwt_time_to_live

    def create_jwt_from_user_identity(self, user_identity: UserIdentity) -> str:
        """
        Create a new JWT with the payload containing the user identity provided.
        The JWT payload also contains an expiration timestamp for the token.
        The JWT signature is produced using the symmetric HS256 algorithm.

        :param user_identity: user identity to insert into the JWT payload.
        :return: the generated JWT as string.
        """
        expiration_timestamp = datetime.now() + self._jwt_time_to_live

        payload = TokenPayload(user_identity=user_identity, exp=expiration_timestamp)
        payload_dict = payload.dict()
        # The `exp` field is the reserved claim in the JWT standard used to identify the expiration timestamp.
        # (https://pyjwt.readthedocs.io/en/latest/usage.html#expiration-time-claim-exp)
        payload_dict["exp"] = payload.exp.timestamp()

        return jwt.encode(payload=payload_dict, key=self._jwt_secret_key, algorithm="HS256")

    def fetch_payload_from_jwt(self, token: str) -> TokenPayload:
        """
        Retrieve the payload from the provided JWT.
        Note that the `jwt` library automatically checks for validity of the token's signature and whether the token has
        not expired yet. In case these conditions are not satisfied, exceptions are raised.

        :param token: the token to decode.
        :return: the payload fetched from the token.
        """
        token_payload_dict = jwt.decode(
            jwt=token,
            key=self._jwt_secret_key,
            algorithms=["HS256"],
            options={"require": ["exp"]},
        )
        return TokenPayload.model_validate(token_payload_dict)

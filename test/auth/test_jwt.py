from datetime import timedelta
from time import sleep

import pytest
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError

from custom_login_api.auth.jwt import AuthenticationClient
from custom_login_api.models.auth.user_identity import UserIdentity


def test_authentication_client_can_encode_and_decode_token() -> None:
    client = AuthenticationClient(jwt_secret_key="secret", jwt_time_to_live=timedelta(1))
    user_identity = UserIdentity(email="user@gmail.com")
    token = client.create_jwt_from_user_identity(user_identity)
    fetched_payload = client.fetch_payload_from_jwt(token)
    assert fetched_payload.user_identity == user_identity


def test_authentication_client_raises_exception_for_expired_token() -> None:
    client = AuthenticationClient(
        jwt_secret_key="secret", jwt_time_to_live=timedelta(milliseconds=100)
    )
    token = client.create_jwt_from_user_identity(UserIdentity(email="hello"))
    sleep(0.3)
    with pytest.raises(ExpiredSignatureError):
        client.fetch_payload_from_jwt(token)


def test_authentication_client_raises_exception_for_forged_token() -> None:
    forged_tokens_client = AuthenticationClient(
        jwt_secret_key="i-dont-know-the-secret", jwt_time_to_live=timedelta(1)
    )
    user_identity = UserIdentity(email="user@gmail.com")
    forged_token = forged_tokens_client.create_jwt_from_user_identity(user_identity)

    client = AuthenticationClient(jwt_secret_key="secret", jwt_time_to_live=timedelta(1))
    with pytest.raises(InvalidSignatureError):
        client.fetch_payload_from_jwt(forged_token)

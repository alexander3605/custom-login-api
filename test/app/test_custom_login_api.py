import json
import random
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient
from pydantic.error_wrappers import ValidationError

from custom_login_api.app.config import load_config
from custom_login_api.app.custom_login_api import CustomLoginAPI
from custom_login_api.auth.jwt import AuthenticationClient
from custom_login_api.models.api.login_request import LoginRequest, LoginRequestWithOtp
from custom_login_api.models.api.successful_login_response import SuccessfulLoginResponse
from custom_login_api.models.api.user_registration_data import UserRegistrationData


def get_test_api(temporary_sqlite_db_directory: str) -> TestClient:
    """
    Testing helper, which returns a fully working API client, which is connected a database in the provided temporary
    folder.
    """
    config = load_config()
    config.database.sqlite_database_name = f"{temporary_sqlite_db_directory}/test.db"
    app = CustomLoginAPI.from_config(config=config)
    app.add_api_endpoints()
    return TestClient(app)


def check_is_valid_jwt_token(token: str) -> None:
    config = load_config()
    client = AuthenticationClient(config.auth.jwt_secret, config.auth.jwt_time_to_live)
    try:
        client.fetch_payload_from_jwt(token=token)
    except Exception as e:
        raise AssertionError from e


def test_api_not_found_endpoint() -> None:
    """
    Test that a 404 status code is returned for non-existing endpoints.
    """
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        response = test_client.get("/")
        assert response.status_code == 404


def test_api_register_successful() -> None:
    """Test that the registration can be performed successfully."""
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        response = test_client.post(
            url="/register", content=json.dumps(UserRegistrationData.mock().dict())
        )
        assert response.status_code == 201


def test_api_register_error_on_double_registration() -> None:
    """Test that the API returns an error code when trying to login twice the same user."""
    user_registration = UserRegistrationData.mock()

    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201
        # Second registration of the same user
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 400

        # Second registration of the same email
        response = test_client.post(
            url="/register",
            content=json.dumps(
                UserRegistrationData(
                    email=user_registration.email,
                    password="hi",
                    name="jose",
                    surname="maria",
                    enable_2fa=True,
                ).dict()
            ),
        )
        assert response.status_code == 400


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"email": "hello@gmail.com"},
        {
            "email": "hello@gmail.com",
            "password": "hi",
            "name": "jose",
            "surname": "",
            "enable_2fa": "true",
        },
        {
            "email": "not.an.email",
            "password": "hi",
            "name": "jose",
            "surname": "maria",
            "enable_2fa": "false",
        },
    ],
)
def test_api_register_error_on_invalid_data(data: dict[str, str]) -> None:
    """Test that the register endpoint returns HTTP 400 when the provided data is invalid."""
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        response = test_client.post(url="/register", content=json.dumps(data))
        assert response.status_code == 400


def test_api_login_successful() -> None:
    """Test the correct flow for basic login."""
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        # Register user
        user_registration = UserRegistrationData(
            email="jose@email.com",
            password="hi",
            name="jose",
            surname="maria",
            enable_2fa=False,
        )
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201
        # Login
        login_request = LoginRequest(
            email=user_registration.email, password=user_registration.password
        )
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 200
        check_is_valid_jwt_token(SuccessfulLoginResponse.parse_raw(response.content).token)

        # Login can be repeated multiple times with the same result
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 200
        check_is_valid_jwt_token(SuccessfulLoginResponse.parse_raw(response.content).token)


def test_api_login_unsuccessful_if_2fa_enabled() -> None:
    """
    Test that the API does not produce a JWT if a user with 2FA enabled tries to login from the basic endpoint.
    """
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        # Register user
        user_registration = UserRegistrationData(
            email="jose@email.com",
            password="hi",
            name="jose",
            surname="maria",
            enable_2fa=True,
        )
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201
        # Login
        login_request = LoginRequest(
            email=user_registration.email, password=user_registration.password
        )
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 202
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)


def test_api_login_unsuccessful_if_wrong_email_or_password() -> None:
    """
    Test that an error code is returned if the email or password provided for login are wrong.
    """
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        # Register user
        user_registration = UserRegistrationData(
            email="jose@email.com",
            password="hi",
            name="jose",
            surname="maria",
            enable_2fa=True,
        )
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201

        # Login - wrong email
        login_request = LoginRequest(
            email="anotheruser@gmail.com", password=user_registration.password
        )
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 401
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

        # Login - wrong password
        login_request = LoginRequest(email=user_registration.email, password="wrong-password")
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 401
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)


def test_api_login_2fa_successful() -> None:
    """
    Test correct flow for 2FA login.
    """
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        # Register user
        user_registration = UserRegistrationData(
            email="jose@email.com",
            password="hi",
            name="jose",
            surname="maria",
            enable_2fa=True,
        )
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201
        # Login --> produce OTP
        login_request = LoginRequest(
            email=user_registration.email, password=user_registration.password
        )
        random.seed(42)  # This will make the OTP generation to return "6022-7680"
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 202
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

        # Login 2FA
        login_request_with_otp = LoginRequestWithOtp(
            email=user_registration.email, password=user_registration.password, otp="6022-7680"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 200
        check_is_valid_jwt_token(SuccessfulLoginResponse.parse_raw(response.content).token)

        # Login 2FA - can be repeated
        login_request_with_otp = LoginRequestWithOtp(
            email=user_registration.email, password=user_registration.password, otp="6022-7680"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 200
        check_is_valid_jwt_token(SuccessfulLoginResponse.parse_raw(response.content).token)


def test_api_login_2fa_unsuccessful() -> None:
    """
    Test that an error code is returned if the email or password or OTP provided for login are wrong.
    """
    with TemporaryDirectory() as temp_dir:
        test_client = get_test_api(temporary_sqlite_db_directory=temp_dir)
        # Register user
        user_registration = UserRegistrationData(
            email="jose@email.com",
            password="hi",
            name="jose",
            surname="maria",
            enable_2fa=True,
        )
        response = test_client.post(url="/register", content=json.dumps(user_registration.dict()))
        assert response.status_code == 201
        # Login --> produce OTP
        login_request = LoginRequest(
            email=user_registration.email, password=user_registration.password
        )
        random.seed(42)  # This will make the OTP generation to return "6022-7680"
        response = test_client.post(url="/login", content=json.dumps(login_request.dict()))
        assert response.status_code == 202
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

        # Login 2FA - successful, sanity check
        login_request_with_otp = LoginRequestWithOtp(
            email=user_registration.email, password=user_registration.password, otp="6022-7680"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 200
        check_is_valid_jwt_token(SuccessfulLoginResponse.parse_raw(response.content).token)

        # Login 2FA - wrong OTP
        login_request_with_otp = LoginRequestWithOtp(
            email=user_registration.email, password=user_registration.password, otp="1234-5678"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 401
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

        # Login 2FA - wrong email
        login_request_with_otp = LoginRequestWithOtp(
            email="anotheruser@gmail.com", password=user_registration.password, otp="6022-7680"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 401
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

        # Login 2FA - wrong password
        login_request_with_otp = LoginRequestWithOtp(
            email="anotheruser@gmail.com", password=user_registration.password, otp="6022-7680"
        )
        response = test_client.post(
            url="/login-2fa", content=json.dumps(login_request_with_otp.dict())
        )
        assert response.status_code == 401
        with pytest.raises(ValidationError):
            SuccessfulLoginResponse.parse_raw(response.content)

from __future__ import annotations

import json
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, status
from pydantic.error_wrappers import ValidationError

from custom_login_api.app.config import Config
from custom_login_api.auth.jwt import AuthenticationClient
from custom_login_api.auth.otp import create_otp
from custom_login_api.database.otp_table_client import OtpTableClient
from custom_login_api.database.sqlite_database_client import SqliteDatabaseClient
from custom_login_api.database.users_table_client import UsersTableClient
from custom_login_api.email.email_client import EmailClient
from custom_login_api.email.print_to_terminal_email_client import PrintToTerminalEmailClient
from custom_login_api.models.api.login_request import LoginRequest, LoginRequestWithOtp
from custom_login_api.models.api.successful_login_response import SuccessfulLoginResponse
from custom_login_api.models.api.user_registration_data import UserRegistrationData
from custom_login_api.models.auth.user_identity import UserIdentity
from custom_login_api.models.exceptions import (
    InvalidOtpException,
    UserAlreadyRegisteredException,
    UserNotRegisteredException,
)


class CustomLoginAPI(FastAPI):
    """FastAPI-based API app for handling sign-up and login operations."""

    def __init__(
        self,
        users_table_client: UsersTableClient,
        otp_table_client: OtpTableClient,
        auth_client: AuthenticationClient,
        email_client: EmailClient,
    ):
        """
        Constructor which uses the clients needed for the API app to work.

        :param users_table_client: client to handle DB operations regarding users.
        :param otp_table_client: client to handle DB operations regarding one-time-passwords.
        :param auth_client: client to handle authentication operations.
        :param email_client: client to handle sending of emails.
        """
        super().__init__(
            title="Custom Login API",
            description="A custom backend service to manage sign-up and sign-in operations.",
            docs_url="/docs/swagger",
            openapi_url="/docs/openapi.json",
            redoc_url="/docs/redoc",
        )
        self.users_table_client = users_table_client
        self.otp_table_client = otp_table_client
        self.auth_client = auth_client
        self.email_client = email_client

        # Initialize DB tables.
        self.users_table_client.create_table()
        self.otp_table_client.create_table()

    @classmethod
    def from_config(
        cls,
        config: Config,
    ) -> CustomLoginAPI:
        """
        Constructor which builds the clients using the settings contained in the provided config.

        :param config: set of settings used to set up the API app clients.
        :return: constructed CustomLoginAPI object.
        """
        database_client = SqliteDatabaseClient(database_name=config.database.sqlite_database_name)

        return cls(
            users_table_client=UsersTableClient(
                database_client=database_client, users_table_name=config.database.users_table_name
            ),
            otp_table_client=OtpTableClient(
                database_client=database_client,
                otp_table_name=config.database.otp_table_name,
                otp_time_to_live=config.auth.otp_time_to_live,
            ),
            auth_client=AuthenticationClient(
                jwt_secret_key=config.auth.jwt_secret, jwt_time_to_live=config.auth.jwt_time_to_live
            ),
            email_client=PrintToTerminalEmailClient(),
        )

    def _add_register_endpoint(self) -> None:
        """
        This function adds to the app the API endpoint which handles users sign-up.
        This endpoint returns an HTTP_201_CREATED status code if the sign-up process is successful.
        If the user provides invalid sign up details, or if the provided email address is already registered, the
        endpoint returns an HTTP_400_BAD_REQUEST.
        """

        @self.post(
            "/register",
            description=(
                "API endpoint which allows users to sign-up.\n\n"
                "# Payload schema\n\n"
                f"```json\n{UserRegistrationData.schema_json(indent=2)}\n```\n\n"
                "# Example payload\n\n"
                f"```json\n{json.dumps(UserRegistrationData.mock().dict(), indent=2)}\n```\n\n"
            ),
            status_code=status.HTTP_201_CREATED,
            responses={
                status.HTTP_201_CREATED: {
                    "description": "The registration was successful",
                },
                status.HTTP_400_BAD_REQUEST: {
                    "description": (
                        "The information provided for the registration is not valid, or the email address is already"
                        " registered. Please check the error message returned by the API."
                    ),
                },
            },
        )
        async def register(raw_request: Request) -> None:
            try:
                user_data = UserRegistrationData.parse_raw(await raw_request.body())
            except ValidationError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The information provided for the registration is not valid.",
                )

            # Register user in the database.
            try:
                self.users_table_client.register_user(new_user=user_data)
            except UserAlreadyRegisteredException:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The email address is already registered.",
                )

    def _run_common_login(self, email: str, password: str) -> bool:
        """
        This function checks the login request against the registered users table in the database.
        If the user is not registered, or the password is incorrect, the function raises an HTTP 401 UNAUTHORIZED
        exception.
        If the registration and password checks are successful, the function returns whether the user has 2FA enabled.

        :param email: the email provided by the user attempting to log in.
        :param password: the password provided by the user attempting to log in.

        :return: whether the user has 2FA enabled.
        """
        login_error_response = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The email address and password combination is incorrect.",
        )

        try:
            (
                registered_password,
                has_2fa_enabled,
            ) = self.users_table_client.get_password_and_2fa_for_email(email=email)
        except UserNotRegisteredException:
            raise login_error_response

        if password != registered_password:
            raise login_error_response

        return has_2fa_enabled

    def _add_login_endpoint(self) -> None:
        """
        This function adds to the app the API endpoint which handles users sign-in.
        This endpoint returns:
            - HTTP_200_OK: if the sign-in process is successful. In this case, the response contains the JWT to use for
                session management.
            - HTTP_202_ACCEPTED: if the sign-in information provided is correct, but the user has 2FA enabled. In this
                case the app sends an email to the user with the OTP to use for 2FA.
            - HTTP_401_UNAUTHORIZED: if the sign-in information provided is incorrect or does not match any registered
                user.
        """

        @self.post(
            "/login",
            description=(
                "API endpoint which allows users to log in, by providing their email address and password."
                " Users that do not have 2FA enabled must use this endpoint for logging in. Users that have 2FA"
                " enabled must use this endpoint to trigger the sending of the OTP via email; afterwards they"
                " must use the `/login-2fa` endpoint for logging in using the received OTP.\n\n"
                "# Payload schema definition\n\n"
                f"```json\n{LoginRequest.schema_json(indent=2)}\n```\n\n"
                "# Example payload\n\n"
                f"```json\n{json.dumps(LoginRequest.mock().dict(), indent=2)}\n```\n\n"
            ),
            status_code=status.HTTP_200_OK,
            response_model=SuccessfulLoginResponse,
            responses={
                status.HTTP_200_OK: {
                    "description": (
                        "The sign-in process was successful. In this case, the response contains the JWT to use for"
                        " session management"
                    ),
                },
                status.HTTP_202_ACCEPTED: {
                    "description": (
                        "The sign-in information provided is correct, but the user has 2FA enabled. In this case the"
                        " app sends an email to the user with the OTP to use for 2FA"
                    ),
                },
                status.HTTP_401_UNAUTHORIZED: {
                    "description": (
                        "The information provided for the sign in invalid or does not match any registered user."
                        " Please check the error message returned by the API."
                    ),
                },
            },
        )
        async def login(raw_request: Request) -> SuccessfulLoginResponse:
            try:
                login_request = LoginRequest.parse_raw(await raw_request.body())
            except ValidationError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The information provided for the login is not valid.",
                )

            has_2fa_enabled = self._run_common_login(
                email=login_request.email, password=login_request.password
            )

            if has_2fa_enabled:
                otp = create_otp()
                self.otp_table_client.register_otp_for_email(otp=otp, email=login_request.email)

                self.email_client.send_message(
                    recipient_email=login_request.email, content=f"Your OTP for 2FA is: `{otp}`"
                )

                raise HTTPException(
                    status_code=status.HTTP_202_ACCEPTED,
                    detail="You have 2-factor-authentication enabled. Your OTP has been emailed to you. Please use the "
                    "'/login-2fa' API endpoint to login using your OTP.",
                )

            return SuccessfulLoginResponse(
                token=self.auth_client.create_jwt_from_user_identity(
                    user_identity=UserIdentity(email=login_request.email)
                )
            )

    def _add_login_2fa_endpoint(self) -> None:
        """
        This function adds to the app the API endpoint which handles users sign-in for users that have 2FA enabled and
        have already received the OTP.
        This endpoint returns:
            - HTTP_200_OK: if the sign-in process is successful. In this case, the response contains the JWT to use for
                session management.
            - HTTP_401_UNAUTHORIZED: if the sign-in information provided is invalid or does not match any registered
                user, or if the OTP provided by the user has expired. This status code is returned also if the sign-in
                information provided is correct but the user does not have 2FA enabled.
        """

        @self.post(
            "/login-2fa",
            description=(
                "API endpoint which allows users that have 2FA enabled to log in, by providing their email "
                "address, password, and the OTP received by email.\n\n"
                "# Payload schema definition\n\n"
                f"```json\n{LoginRequestWithOtp.schema_json(indent=2)}\n```\n\n"
                "# Example payload\n\n"
                f"```json\n{json.dumps(LoginRequestWithOtp.mock().dict(), indent=2)}\n```\n\n"
            ),
            status_code=status.HTTP_200_OK,
            response_model=SuccessfulLoginResponse,
            responses={
                status.HTTP_200_OK: {
                    "description": (
                        "The sign-in process was successful. In this case, the response contains the JWT to use for"
                        " session management"
                    ),
                },
                status.HTTP_401_UNAUTHORIZED: {
                    "description": (
                        "The sign-in information provided is invalid or does not match any registered user, or if the"
                        " OTP provided by the user has expired. This status code is returned also if the sign-in"
                        " information provided is correct but the user does not have 2FA enabled. Please check the"
                        " error message returned by the API."
                    ),
                },
            },
        )
        async def login_2fa(raw_request: Request) -> SuccessfulLoginResponse:
            try:
                login_request = LoginRequestWithOtp.parse_raw(await raw_request.body())
            except ValidationError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The information provided for the login is not valid.",
                )

            has_2fa_enabled = self._run_common_login(
                email=login_request.email, password=login_request.password
            )

            if not has_2fa_enabled:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The user does not have 2FA enabled. Please log in using the `/login` API endpoint.",
                )

            try:
                otp_expiration = self.otp_table_client.fetch_otp_expiration(
                    otp=login_request.otp, email=login_request.email
                )
            except InvalidOtpException:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The OTP provided is not correct.",
                )

            # Check if OTP has expired.
            if otp_expiration < datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The OTP provided has expired. Generate a new one using the `/login` API endpoint.",
                )

            return SuccessfulLoginResponse(
                token=self.auth_client.create_jwt_from_user_identity(
                    user_identity=UserIdentity(email=login_request.email)
                )
            )

    def add_api_endpoints(self) -> None:
        """Populate the application with all the API endpoints."""
        self._add_register_endpoint()
        self._add_login_endpoint()
        self._add_login_2fa_endpoint()

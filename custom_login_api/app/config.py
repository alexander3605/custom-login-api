from datetime import timedelta

import environ


@environ.config(prefix="")
class Config:
    """
    Configuration of the runtime of the application.
    """

    @environ.config
    class Database:
        sqlite_database_name: str = environ.var(
            default="login-database.db", help="The name of the SQLite database used by the API."
        )
        users_table_name: str = environ.var(
            default="users", help="The name of the database table containing registered users."
        )
        otp_table_name: str = environ.var(
            default="otp", help="The name of the database table containing OTPs."
        )

    @environ.config
    class Auth:
        # TODO: In a production scenario, the default value for this secret should not be hardcoded in the source code,
        #  but fetched by the service from a secrets management service such as Vault (https://www.vaultproject.io/).
        jwt_secret: str = environ.var(
            default="my-super-secret-jwt-secret",
            help="The secret key used for creating the signature of JWTs.",
        )
        jwt_time_to_live: timedelta = environ.var(
            default=60,
            converter=lambda s: timedelta(seconds=int(s)),
            help="The time to live used to set the expiration timestamp of JWTs, expressed in seconds.",
        )
        otp_time_to_live: timedelta = environ.var(
            default=5 * 60,
            converter=lambda s: timedelta(seconds=int(s)),
            help="The time to live used to set the expiration timestamp of 2FA OTPs, expressed in seconds.",
        )

    database: Database = environ.group(Database)
    auth: Auth = environ.group(Auth)


def load_config() -> Config:
    """
    Load the application configuration.
    """
    return environ.to_config(Config)

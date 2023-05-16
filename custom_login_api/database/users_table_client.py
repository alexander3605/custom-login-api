from custom_login_api.database.database_client import DatabaseClient
from custom_login_api.database.table_client import TableClient
from custom_login_api.models.api.user_registration_data import UserRegistrationData
from custom_login_api.models.exceptions import (
    UserAlreadyRegisteredException,
    UserNotRegisteredException,
)


class UsersTableClient(TableClient):
    """
    Client to manage the table containing information about the registered users.
    """

    def __init__(
        self,
        database_client: DatabaseClient,
        users_table_name: str,
    ):
        """
        Constructor for the client.

        :param database_client: the client managing interactions with the underlying SQL database.
        :param users_table_name: the identifier of the SQL table containing information about registered users.
        """
        self._client = database_client
        self._users_table_name = users_table_name

    def create_table(self) -> None:
        """
        Create the database table managed by the client, if it does not exist already.

        The EMAIL field is used as primary key of the table.
        """
        create_table_command = f"""
            CREATE TABLE IF NOT EXISTS {self._users_table_name} (
                email TEXT NOT NULL PRIMARY KEY,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                surname TEXT NOT NULL,
                uses_2fa BOOLEAN NOT NULL
            )
        """
        self._client.execute(sql_command=create_table_command)

    def is_email_address_registered(self, email: str) -> bool:
        """
        Check whether the provided email address already exists in the table.

        :param email: the email address to check.
        :return: whether the email address is already present in the table.
        """
        fetch_matching_emails_query = f"""
            SELECT email
            FROM {self._users_table_name}
            WHERE email = ?
        """
        result = self._client.execute(sql_command=fetch_matching_emails_query, parameters=(email,))
        return result.fetchone() is not None

    def register_user(self, new_user: UserRegistrationData) -> None:
        """
        Record the user into the table managed by the client.

        :param new_user: struct containing all the fields necessary for user registration.
        :raises UserAlreadyRegisteredException: if the email address is already registered in the table.
        """
        if self.is_email_address_registered(new_user.email):
            raise UserAlreadyRegisteredException

        insert_cmd = f"INSERT INTO {self._users_table_name} values(?, ?, ?, ?, ?)"
        new_user_data = (
            new_user.email,
            new_user.password,
            new_user.name,
            new_user.surname,
            new_user.enable_2fa,
        )
        self._client.execute(sql_command=insert_cmd, parameters=new_user_data)

    def get_password_and_2fa_for_email(self, email: str) -> tuple[str, bool]:
        """
        For the provided user's email address, fetch the password and 2FA preference specified upon registration.
        :param email: the email address of the user.
        :return: tuple containing the password and whether 2FA is enabled for the user.

        :raises UserNotRegisteredException: if the email address provided is not registered.
        """
        fetch_password_for_email_query = f"""
            SELECT password, uses_2fa
            FROM {self._users_table_name}
            WHERE email = ?
        """
        result = self._client.execute(
            sql_command=fetch_password_for_email_query, parameters=(email,)
        )
        result_values = result.fetchone()
        if result_values is None:
            raise UserNotRegisteredException

        password, uses_2fa = result_values
        return password, uses_2fa

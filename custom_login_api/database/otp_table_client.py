from datetime import datetime, timedelta

from custom_login_api.database.database_client import DatabaseClient
from custom_login_api.database.table_client import TableClient
from custom_login_api.models.exceptions import InvalidOtpException


class OtpTableClient(TableClient):
    """
    Client to manage the table containing information about the OTPs used for 2FA.
    """

    def __init__(
        self,
        database_client: DatabaseClient,
        otp_table_name: str,
        otp_time_to_live: timedelta,
    ):
        """
        Constructor for the client.

        :param database_client: the client managing interactions with the underlying SQL database.
        :param otp_table_name: the identifier of the SQL table containing information about OTPs.
        :param otp_time_to_live: the validity period of the generated OTPs.
        """
        self._client = database_client
        self._otp_table_name = otp_table_name
        self._otp_time_to_live = otp_time_to_live

    def create_table(self) -> None:
        """
        Create the database table managed by the client, if it does not exist already.

        The OTP and EMAIL fields are used jointly as primary key of the table. This is because we allow the same OTP
        value to be used for logging in different users. However, the same user cannot have the same OTP produced
        multiple times.
        """
        create_table_command = f"""
            CREATE TABLE IF NOT EXISTS {self._otp_table_name} (
                otp TEXT NOT NULL,
                email TEXT NOT NULL,
                expiration TIMESTAMP NOT NULL,
                PRIMARY KEY (otp, email)
            )
        """
        self._client.execute(sql_command=create_table_command)

    def register_otp_for_email(self, otp: str, email: str) -> None:
        """
        Record the OTP into the table managed by client.

        :param otp: the new OTP to store in the table.
        :param email: the email of the user that will use the OTP for logging in.
        """
        register_otp_cmd = f"INSERT INTO {self._otp_table_name} values(?, ?, ?)"

        new_otp_data = (
            otp,
            email,
            (datetime.now() + self._otp_time_to_live),
        )
        self._client.execute(sql_command=register_otp_cmd, parameters=new_otp_data)

    def fetch_otp_expiration(self, otp: str, email: str) -> datetime:
        """
        Retrieve the expiration timestamp for the OTP and email provided.

        :param otp: the OTP for which to retrieve the expiration timestamp.
        :param email: the email address of the user which provided the OTP.
        :return: the expiration timestamp for the OTP.

        :raises InvalidOtpException: if the OTP is not registered for the provided email.
        """
        fetch_expiration_query = f"""
            SELECT expiration
            FROM {self._otp_table_name}
            WHERE email = ?
            AND otp = ?
        """
        query_params = (
            email,
            otp,
        )
        result = self._client.execute(sql_command=fetch_expiration_query, parameters=query_params)
        result_row = result.fetchone()
        if result_row is None:
            raise InvalidOtpException
        return datetime.fromisoformat(result_row[0])

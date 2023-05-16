import sqlite3
from sqlite3 import Cursor
from typing import Any, Optional

from custom_login_api.database.database_client import DatabaseClient


class SqliteDatabaseClient(DatabaseClient):
    def __init__(self, database_name: str):
        self._database_name = database_name

    def execute(self, sql_command: str, parameters: Optional[tuple[Any, ...]] = None) -> Cursor:
        with sqlite3.connect(self._database_name) as db_connection:
            return (
                db_connection.execute(sql_command, parameters)
                if parameters is not None
                else db_connection.execute(sql_command)
            )

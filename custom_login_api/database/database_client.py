from abc import ABC, abstractmethod
from typing import Any, Optional


class DatabaseClient(ABC):
    """
    Abstract class defining the basic primitives needed by all SQL database connectors.

    NOTE: in this project, we only have one database connector (based on SQLite3), but if others would be implemented,
    they would subclass this class.
    """

    @abstractmethod
    def execute(self, sql_command: str, parameters: Optional[tuple[Any, ...]] = None) -> Any:
        """
        Primitive to execute an SQL command with optional parameters.

        :param sql_command: SQL command to execute.
        :param parameters: optional parameters to be inserted in the SQL command.
        :return: the result of the operation.
        """
        pass

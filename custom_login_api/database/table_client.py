from abc import ABC, abstractmethod


class TableClient(ABC):
    """
    Abstract class defining the basic primitives needed by all clients managing SQL tables.
    """

    @abstractmethod
    def create_table(self) -> None:
        """
        Create the database table managed by the client, if it does not exist already.
        """

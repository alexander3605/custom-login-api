from abc import ABC, abstractmethod


class EmailClient(ABC):
    """
    Abstract class defining the basic primitives needed by all clients capable of sending email on behalf of the login
    service.

    NOTE: in this project, we only have one email client (which prints to terminal the email content), but if others
    would be implemented, they would subclass this class.
    """

    @abstractmethod
    def send_message(self, recipient_email: str, content: str) -> None:
        """
        Send a message to the specified recipient.

        :param recipient_email: the email address of the recipient.
        :param content: the email content.
        """

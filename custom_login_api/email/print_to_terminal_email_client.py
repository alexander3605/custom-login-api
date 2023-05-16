from custom_login_api.email.email_client import EmailClient


class PrintToTerminalEmailClient(EmailClient):
    """
    Mock email client, which prints to STDOUT the email content.
    """

    def send_message(self, recipient_email: str, content: str) -> None:
        """
        Mock email sending method, which prints to STDOUT the email content.

        :param recipient_email: the email address of the recipient.
        :param content: the email content.
        """
        print("Mocking email to be sent to:", recipient_email)
        print("====== BODY START ======")
        print(content)
        print("====== BODY END ========")

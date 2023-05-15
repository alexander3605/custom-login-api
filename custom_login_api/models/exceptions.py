# Registration and login exceptions.
class UserAlreadyRegisteredException(Exception):
    """
    Exception raised when trying to register a user which is already registered.
    """


class UserNotRegisteredException(Exception):
    """
    Exception raised when the target user is not registered in the platform.
    """


# OTP-related exceptions.
class InvalidOtpException(Exception):
    """
    Exception raised when the OTP provided is invalid.
    """

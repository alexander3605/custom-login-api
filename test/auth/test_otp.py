import random

from custom_login_api.auth.otp import create_otp


def test_otp_generation() -> None:
    random.seed(42)
    assert create_otp() == "6022-7680"
    assert create_otp() == "4025-0165"

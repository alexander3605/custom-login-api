from random import choices


def create_otp() -> str:
    """
    Create an 8-digit one-time password string with the structure `XXXX-XXXX`.
    """
    otp_digits = choices(population=[str(n) for n in range(0, 10)], k=8)
    return f"{''.join(otp_digits[:4])}-{''.join(otp_digits[4:])}"

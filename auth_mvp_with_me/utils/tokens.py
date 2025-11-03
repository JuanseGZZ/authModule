
import secrets

def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)

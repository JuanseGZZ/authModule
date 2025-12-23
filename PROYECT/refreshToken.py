import hashlib
import datetime
import secrets

class RefreshToken:
    def __init__(self, user_id: str) -> None:
        now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        salt = secrets.token_hex(16)
        raw = f"{user_id}|{now}|{salt}".encode("utf-8")
        self._token = hashlib.sha256(raw).hexdigest()

    def getRefres(self) -> str:
        return self._token

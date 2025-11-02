import bcrypt
import jwt
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from app.core.config import settings

def hash_password(password: str) -> str:
    rounds = settings.AUTH_BCRYPT_ROUNDS
    salt = bcrypt.gensalt(rounds)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def make_access_token(sub: str) -> Tuple[str, str]:
    iat = int(time.time())
    exp = iat + settings.AUTH_ACCESS_TTL_MIN * 60
    jti = str(uuid.uuid4())
    payload = {
        "sub": sub,
        "iss": settings.AUTH_ISS,
        "aud": settings.AUTH_AUD,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    }
    token = jwt.encode(payload, settings.AUTH_JWT_SECRET, algorithm="HS256")
    return token, jti

def sha256_bytes(raw: str) -> bytes:
    import hashlib
    return hashlib.sha256(raw.encode()).digest()

def gen_refresh_token() -> str:
    # Opaque random token (base64url-like)
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars

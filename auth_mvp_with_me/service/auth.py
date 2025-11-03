
import os, time, uuid, hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from db.auth import DB
from utils.crypto import sign_jws, encrypt_jwe_nested, verify_password, decrypt_jwe_nested, verify_jws
from utils.tokens import random_token
from utils.jwks import get_active_kids
from models.types import Claims

ACCESS_TTL_MIN = int(os.getenv("ACCESS_TTL_MIN", "15"))
REFRESH_TTL_DAYS = int(os.getenv("REFRESH_TTL_DAYS", "30"))

class AuthService:
    def __init__(self):
        self.db = DB()

    def register(self, email: str, password: str) -> Dict[str, Any]:
        if not email or not password:
            raise ValueError("email y password son requeridos")
        return self.db.create_user(email, password)

    def login(self, email: str, password: str, user_agent: Optional[str], ip: Optional[str]) -> Dict[str, Any]:
        user = self.db.get_user_by_email(email)
        if not user or not verify_password(password, user["password_hash"].tobytes() if hasattr(user["password_hash"], "tobytes") else user["password_hash"]):
            raise ValueError("Credenciales inválidas")
        return self._issue_tokens(user_id=user["id"], email=user["email"], user_agent=user_agent, ip=ip)

    def refresh(self, refresh_raw: str, user_agent: Optional[str], ip: Optional[str]) -> Dict[str, Any]:
        if not refresh_raw:
            raise ValueError("refresh_token requerido")
        old = self.db.get_refresh_by_hash(self._sha256(refresh_raw))
        if not old or old["revoked_at"] is not None or old["expires_at"] < datetime.now(timezone.utc):
            raise ValueError("refresh_token inválido o expirado")
        # rotate
        self.db.revoke_refresh(old["id"])
        return self._issue_tokens(user_id=old["user_id"], email=None, user_agent=user_agent, ip=ip, parent_id=old["id"])

    def logout(self, refresh_raw: str) -> None:
        row = self.db.get_refresh_by_hash(self._sha256(refresh_raw))
        if not row:
            raise ValueError("refresh_token inválido")
        self.db.revoke_refresh(row["id"])

    def _issue_tokens(self, user_id: str, email: Optional[str], user_agent: Optional[str], ip: Optional[str], parent_id: Optional[str]=None) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=ACCESS_TTL_MIN)
        claims = Claims(sub=user_id, iat=int(now.timestamp()), exp=int(exp.timestamp()))
        if email:
            claims.email = email  # optional
        jws = sign_jws(claims.model_dump())
        access = encrypt_jwe_nested(jws)
        refresh_raw = random_token(64)
        refresh_hash = self._sha256(refresh_raw)
        self.db.store_refresh(user_id=user_id, token_hash=refresh_hash, ttl_days=REFRESH_TTL_DAYS, parent_id=parent_id, user_agent=user_agent, ip=ip)
        return {
            "access_token": access,
            "token_type": "NESTED_JWE_JWS",
            "expires_in": ACCESS_TTL_MIN * 60,
            "refresh_token": refresh_raw
        }

    @staticmethod
    def _sha256(raw: str) -> bytes:
        return hashlib.sha256(raw.encode("utf-8")).digest()


def me(self, access_token: str):
    if not access_token:
        raise ValueError("token requerido")
    jws = decrypt_jwe_nested(access_token)
    claims = verify_jws(jws)
    # expiración mínima
    now = int(datetime.now(timezone.utc).timestamp())
    if claims.get("exp") is None or claims["exp"] < now:
        raise ValueError("token expirado")
    user = self.db.get_user_by_id(claims["sub"])
    if not user:
        raise ValueError("usuario no encontrado")
    return {"id": str(user["id"]), "email": user["email"]}

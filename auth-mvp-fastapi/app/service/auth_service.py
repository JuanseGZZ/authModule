from typing import Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from app.db.database import get_session
from app.db.repositories.auth_repo import AuthRepo
from app.utils.security import hash_password, verify_password, make_access_token, gen_refresh_token
from app.core.errors import AuthErrorCodes, http_401, http_409
from app.models.orm import User, RefreshToken

class AuthService:
    def __init__(self, session: AsyncSession):
        self.repo = AuthRepo(session)

    async def register(self, email: str, password: str) -> User:
        existing = await self.repo.get_user_by_email(email)
        if existing:
            http_409(AuthErrorCodes.CONFLICT_EMAIL_TAKEN, "Email ya registrado.")
        pwd_hash = hash_password(password)
        user = await self.repo.create_user(email=email, password_hash=pwd_hash)
        return user

    async def login(self, email: str, password: str, ip: Optional[str], user_agent: Optional[str]) -> Tuple[str, str, str]:
        user = await self.repo.get_user_by_email(email)
        if not user or not verify_password(password, user.password_hash):
            http_401(AuthErrorCodes.AUTH_INVALID_CREDENTIALS, "Credenciales inválidas.")
        access, jti = make_access_token(str(user.id))
        refresh_raw = gen_refresh_token()
        await self.repo.create_refresh(user_id=user.id, raw_token=refresh_raw, ip=ip, user_agent=user_agent)
        return access, refresh_raw, jti

    async def rotate_refresh(self, refresh_raw: str, ip: Optional[str], user_agent: Optional[str]) -> Tuple[str, str]:
        current = await self.repo.find_refresh(refresh_raw)
        if not current:
            http_401(AuthErrorCodes.AUTH_REFRESH_NOT_FOUND, "Refresh no encontrado.")
        # Verificar expirado / revocado
        from datetime import datetime, timezone
        if current.revoked_at is not None:
            http_401(AuthErrorCodes.AUTH_TOKEN_REVOKED, "Refresh revocado/reusado.")
        if current.expires_at <= datetime.now(timezone.utc):
            http_401(AuthErrorCodes.AUTH_TOKEN_EXPIRED, "Refresh expirado.")

        # Rotación: revocar actual y emitir nuevo vinculado
        await self.repo.revoke_refresh(current)
        new_raw = gen_refresh_token()
        await self.repo.create_refresh(user_id=current.user_id, raw_token=new_raw, parent_id=current.id, ip=ip, user_agent=user_agent)

        # Emitir nuevo access
        access, _ = make_access_token(str(current.user_id))
        return access, new_raw

    async def logout(self, refresh_raw: Optional[str]):
        if not refresh_raw:
            # idempotente: no falla si no viene token
            return
        r = await self.repo.find_refresh(refresh_raw)
        if r:
            await self.repo.revoke_refresh(r)

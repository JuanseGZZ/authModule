from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
from typing import Optional
from app.models.orm import User, RefreshToken
from app.utils.security import sha256_bytes
from app.core.config import settings

class AuthRepo:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_user_by_email(self, email: str) -> Optional[User]:
        res = await self.session.execute(select(User).where(User.email == email))
        return res.scalar_one_or_none()

    async def create_user(self, email: str, password_hash: str) -> User:
        u = User(email=email, password_hash=password_hash)
        self.session.add(u)
        await self.session.flush()
        return u

    async def create_refresh(self, user_id, raw_token: str, parent_id=None, ip=None, user_agent=None) -> RefreshToken:
        token_hash = sha256_bytes(raw_token)
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(days=settings.AUTH_REFRESH_TTL_DAYS)
        rt = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            parent_id=parent_id,
            ip=ip,
            user_agent=user_agent,
        )
        self.session.add(rt)
        await self.session.flush()
        return rt

    async def find_refresh(self, raw_token: str) -> Optional[RefreshToken]:
        token_hash = sha256_bytes(raw_token)
        res = await self.session.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        return res.scalar_one_or_none()

    async def revoke_refresh(self, refresh: RefreshToken):
        refresh.revoked_at = datetime.now(timezone.utc)
        await self.session.flush()

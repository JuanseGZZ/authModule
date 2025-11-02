
import uuid, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from db.models import User, RefreshToken
from utils.env import settings

class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, email: str, password: str) -> User:
        pw_hash = bcrypt.hash(password)
        u = User(email=email, password_hash=pw_hash)
        self.db.add(u)
        self.db.commit()
        self.db.refresh(u)
        return u

    def verify_user(self, email: str, password: str) -> Optional[User]:
        u = self.db.query(User).filter(User.email == email).first()
        if not u:
            return None
        if not bcrypt.verify(password, u.password_hash):
            return None
        if not u.is_active:
            return None
        return u

    def new_refresh(self, user_id: int, parent_jti: Optional[str] = None) -> Tuple[str, str]:
        token = secrets.token_urlsafe(48)
        token_sha = hashlib.sha256(token.encode()).hexdigest()
        jti = uuid.uuid4().hex
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.refresh_ttl)
        r = RefreshToken(
            user_id=user_id,
            token_sha256=token_sha,
            jti=jti,
            parent_jti=parent_jti,
            revoked=False,
            expires_at=expires_at
        )
        self.db.add(r)
        self.db.commit()
        return token, jti

    def rotate_refresh(self, old_token: str) -> Tuple[Optional[RefreshToken], Optional[User], Optional[str]]:
        sha = hashlib.sha256(old_token.encode()).hexdigest()
        r = self.db.query(RefreshToken).filter(RefreshToken.token_sha256 == sha).first()
        if not r:
            return None, None, "refresh_not_found"
        if r.revoked:
            self._revoke_descendants(r.jti)
            return r, r.user, "refresh_reuse_detected"
        if r.expires_at < datetime.now(timezone.utc):
            return r, r.user, "refresh_expired"
        r.revoked = True
        self.db.commit()
        return r, r.user, None

    def _revoke_descendants(self, parent_jti: str):
        q = self.db.query(RefreshToken).filter(RefreshToken.parent_jti == parent_jti, RefreshToken.revoked == False)
        for t in q.all():
            t.revoked = True
        self.db.commit()

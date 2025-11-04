from datetime import datetime
from uuid import UUID
from pydantic import BaseModel

class RefreshToken(BaseModel):
    def __init__(self, id: UUID, user_id: UUID, jti: UUID, token_hash: str,
                 issued_at: datetime, expires_at: datetime, revoked_at: datetime | None,
                 replaced_by: UUID | None, meta: dict):
        self.id = id
        self.user_id = user_id
        self.jti = jti
        self.token_hash = token_hash
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.revoked_at = revoked_at
        self.replaced_by = replaced_by
        self.meta = meta

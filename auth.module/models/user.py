from typing import Dict, Any, List
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel

class User(BaseModel):
    def __init__(self, id: UUID, email: str, username: str, hashed_password: str,
                 access_path: list[int], user_data: Dict[str, Any], is_active: bool, created_at: datetime, updated_at: datetime, powers: List[str], data_user: Dict[str, Any]):
        self.id = id
        self.email = email
        self.username = username
        self.hashed_password = hashed_password
        self.access_path = access_path
        self.user_data = user_data
        self.is_active = is_active
        self.created_at = created_at
        self.updated_at = updated_at
        self.powers = powers
        self.data_user = data_user
    

from dataclasses import dataclass
from typing import Optional

@dataclass
class RefreshToken:
    id: str
    user_id: str
    parent_id: Optional[str]

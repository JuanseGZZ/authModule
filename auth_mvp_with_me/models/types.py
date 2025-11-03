
from pydantic import BaseModel
from typing import Optional

class Claims(BaseModel):
    sub: str
    iat: int
    exp: int
    email: Optional[str] = None

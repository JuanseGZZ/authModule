from pydantic import BaseModel, EmailStr
from typing import Optional
import uuid

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 900

class MeResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    roles: list[str] = []

class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None

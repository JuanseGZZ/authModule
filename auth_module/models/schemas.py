
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"

class AuthBundleResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"

class MeResponse(BaseModel):
    id: int
    email: EmailStr
    is_active: bool

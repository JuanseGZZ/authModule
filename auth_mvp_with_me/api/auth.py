
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from service.auth import AuthService
from utils.security import parse_front_encrypted, bearer_token
from typing import Optional

router = APIRouter()

class RegisterIn(BaseModel):
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class RefreshIn(BaseModel):
    refresh_token: str

class LogoutIn(BaseModel):
    refresh_token: str

svc = AuthService()

def error(code: str, message: str, status: int = 400):
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)

@router.post("/register")
async def register(req: Request, body: RegisterIn):
    data = await parse_front_encrypted(req, body.model_dump())
    try:
        user = svc.register(email=data["email"], password=data["password"])
        return {"id": user["id"], "email": user["email"]}
    except ValueError as e:
        return error("AUTH_REGISTER_FAILED", str(e), 400)

@router.post("/login")
async def login(req: Request, body: LoginIn):
    data = await parse_front_encrypted(req, body.model_dump())
    try:
        tokens = svc.login(email=data["email"], password=data["password"], user_agent=req.headers.get("user-agent"), ip=req.client.host if req.client else None)
        return tokens
    except ValueError as e:
        return error("AUTH_INVALID_CREDENTIALS", str(e), 401)

@router.post("/token/refresh")
async def refresh(req: Request, body: RefreshIn):
    data = await parse_front_encrypted(req, body.model_dump())
    try:
        tokens = svc.refresh(refresh_raw=data["refresh_token"], user_agent=req.headers.get("user-agent"), ip=req.client.host if req.client else None)
        return tokens
    except ValueError as e:
        return error("AUTH_REFRESH_FAILED", str(e), 401)

@router.post("/logout")
async def logout(req: Request, body: LogoutIn):
    data = await parse_front_encrypted(req, body.model_dump())
    try:
        svc.logout(refresh_raw=data["refresh_token"])
        return {"ok": True}
    except ValueError as e:
        return error("AUTH_LOGOUT_FAILED", str(e), 400)


@router.get("/me")
async def me(req: Request):
    tok = bearer_token(req)
    if not tok:
        return error("AUTH_TOKEN_REQUIRED", "Falta Authorization: Bearer <token>", 401)
    try:
        user = svc.me(tok)
        return user
    except ValueError as e:
        return error("AUTH_ME_FAILED", str(e), 401)

# api/auth_api.py
from fastapi import APIRouter, Request, Header, HTTPException
from typing import Optional

router = APIRouter(prefix="/auth", tags=["auth"])

ACCESS_TTL   = 15 * 60         # 15 min
REFRESH_TTL  = 7 * 24 * 3600   # 7 días
ISS          = "https://auth.tuapp.com"
AUD          = "api://core"
COOKIE_DOMAIN= ".tuapp.com"
ALG          = "RS256"

@router.post("/register")
async def post_register(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    # TODO: implementar lógica de registro con email, username, password
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/login")
async def post_login(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    identifier = data.get("email_or_username")
    password = data.get("password")

    # TODO: implementar lógica de login con identifier y password
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/refresh")
async def post_refresh(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    refresh_token = data.get("refresh_token")

    # TODO: implementar lógica de refresh con refresh_token
    raise HTTPException(status_code=501, detail="Not implemented")


@router.post("/logout")
async def post_logout(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    refresh_token = data.get("refresh_token")

    # TODO: implementar lógica de logout con refresh_token
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/protectedApi")
async def protectedApi(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")




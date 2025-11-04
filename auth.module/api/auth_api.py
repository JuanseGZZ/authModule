# api/auth_api.py
from fastapi import APIRouter, Request, Header, HTTPException
from typing import Optional

router = APIRouter(prefix="/auth", tags=["auth"])

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


@router.get("/verify")
def get_verify(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    access_token = authorization.split(" ", 1)[1]

    # TODO: implementar verificación del access_token
    raise HTTPException(status_code=501, detail="Not implemented")

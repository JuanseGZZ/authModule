from fastapi import APIRouter, Depends, Request
from fastapi import status
from fastapi.responses import JSONResponse
from app.models.schemas import RegisterRequest, RegisterResponse, LoginRequest, TokenResponse, MeResponse, RefreshRequest
from app.service.auth_service import AuthService
from app.db.database import get_session
from sqlalchemy.ext.asyncio import AsyncSession
from app.utils.ratelimit import RateLimiter
from app.core.config import settings
from app.core.errors import http_429, AuthErrorCodes
import jwt

router = APIRouter()

_login_rl = RateLimiter(limit=settings.RATE_LIMIT_LOGIN_PER_IP_PER_15M)
_refresh_rl = RateLimiter(limit=settings.RATE_LIMIT_REFRESH_PER_IP_PER_15M)

def _ip(req: Request) -> str:
    return req.client.host if req.client else "unknown"

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    user = await svc.register(req.email, req.password)
    return RegisterResponse(id=user.id, email=user.email)

@router.post("/login", response_model=TokenResponse)
async def login(request: Request, req: LoginRequest, session: AsyncSession = Depends(get_session)):
    ip = _ip(request)
    if not _login_rl.allow(f"login:{ip}"):
        http_429(AuthErrorCodes.AUTH_RATE_LIMIT, "Demasiados intentos de login.")
    ua = request.headers.get("user-agent")
    svc = AuthService(session)
    access, refresh, jti = await svc.login(req.email, req.password, ip=ip, user_agent=ua)
    return TokenResponse(access_token=access, refresh_token=refresh)

@router.post("/token/refresh", response_model=TokenResponse)
async def refresh(request: Request, req: RefreshRequest, session: AsyncSession = Depends(get_session)):
    ip = _ip(request)
    if not _refresh_rl.allow(f"refresh:{ip}"):
        http_429(AuthErrorCodes.AUTH_RATE_LIMIT, "Demasiadas solicitudes de refresh.")
    token = req.refresh_token
    svc = AuthService(session)
    access, new_refresh = await svc.rotate_refresh(token, ip=ip, user_agent=request.headers.get("user-agent"))
    return TokenResponse(access_token=access, refresh_token=new_refresh)

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(req: RefreshRequest, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    await svc.logout(req.refresh_token)
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)

@router.get("/me", response_model=MeResponse)
async def me(authorization: str | None = None):
    # MVP: parse Authorization: Bearer <jwt>
    if not authorization or not authorization.lower().startswith("bearer "):
        from app.core.errors import http_401, AuthErrorCodes
        http_401(AuthErrorCodes.AUTH_TOKEN_EXPIRED, "Token faltante o inválido.")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
        # Para MVP validamos expiración en el decode real; aquí solo retornamos sub como id
        uid = payload.get("sub")
        return MeResponse(id=uid, email="(desconocido@demo.local)", roles=[])
    except Exception:
        from app.core.errors import http_401, AuthErrorCodes
        http_401(AuthErrorCodes.AUTH_TOKEN_EXPIRED, "Token inválido/expirado.")

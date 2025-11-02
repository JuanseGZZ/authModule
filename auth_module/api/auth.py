
from fastapi import APIRouter, Depends, Request, Response, Body
from sqlalchemy.orm import Session
from db.session import get_session
from models.schemas import RegisterRequest, LoginRequest, AuthBundleResponse, TokenResponse, MeResponse
from utils.errors import error_response
from utils.rate_limit import rate_limit
from services.key_stores import KeyStores
from services.crypto_services import TokenSigner, FrontPayloadDecrypter
from services.auth_service import AuthService
from utils.env import settings
from db.models import User

router = APIRouter(tags=["auth"])
ks = KeyStores()
signer = TokenSigner(ks)
front = FrontPayloadDecrypter(ks)

def set_refresh_cookie(resp: Response, token: str):
    resp.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path=settings.refresh_cookie_path,
    )

@router.post("/register")
def register(resp: Response, payload: dict = Body(...), db: Session = Depends(get_session)):
    try:
        payload = front.maybe_decrypt(payload)
    except Exception:
        return error_response("front_decrypt_failed", "Invalid __front_enc__ payload", 400)

    try:
        data = RegisterRequest(**payload)
    except Exception:
        return error_response("invalid_request", "Bad register payload", 400)

    svc = AuthService(db)
    # TODO: uniqueness error codes per YAML
    user = svc.create_user(email=data.email, password=data.password)
    access = signer.issue_access(sub=str(user.id), extra_claims={"email": user.email})
    refresh, jti = svc.new_refresh(user.id, parent_jti=None)
    set_refresh_cookie(resp, refresh)
    return AuthBundleResponse(access_token=access, refresh_token="__in_cookie__")

@router.post("/login")
def login(request: Request, resp: Response, payload: dict = Body(...), db: Session = Depends(get_session)):
    rl = rate_limit(request, rule="5/60")
    if rl:
        return rl
    try:
        payload = front.maybe_decrypt(payload)
    except Exception:
        return error_response("front_decrypt_failed", "Invalid __front_enc__ payload", 400)
    try:
        data = LoginRequest(**payload)
    except Exception:
        return error_response("invalid_request", "Bad login payload", 400)

    svc = AuthService(db)
    user = svc.verify_user(data.email, data.password)
    if not user:
        return error_response("invalid_credentials", "Invalid email or password", 401)

    access = signer.issue_access(sub=str(user.id), extra_claims={"email": user.email})
    refresh, jti = svc.new_refresh(user.id)
    set_refresh_cookie(resp, refresh)
    return AuthBundleResponse(access_token=access, refresh_token="__in_cookie__")

@router.post("/token/refresh")
def refresh_token(request: Request, resp: Response, db: Session = Depends(get_session)):
    rl = rate_limit(request, rule="10/60")
    if rl:
        return rl
    raw = request.cookies.get(settings.refresh_cookie_name)
    if not raw:
        return error_response("missing_refresh", "Refresh token cookie missing", 401)
    svc = AuthService(db)
    prev, user, err = svc.rotate_refresh(raw)
    if err == "refresh_reuse_detected":
        return error_response("refresh_reuse_detected", "Refresh token reuse detected", 401)
    if err == "refresh_expired":
        return error_response("refresh_expired", "Refresh token expired", 401)
    if err == "refresh_not_found":
        return error_response("refresh_invalid", "Invalid refresh token", 401)
    new_refresh, jti = svc.new_refresh(user.id, parent_jti=prev.jti if prev else None)
    access = signer.issue_access(sub=str(user.id), extra_claims={"email": user.email})
    set_refresh_cookie(resp, new_refresh)
    return TokenResponse(access_token=access)

@router.post("/logout")
def logout(resp: Response):
    resp.delete_cookie(settings.refresh_cookie_name, path=settings.refresh_cookie_path)
    return {"ok": True}

@router.get("/me", response_model=MeResponse)
def me(authorization: str | None = None, db: Session = Depends(get_session)):
    if not authorization or not authorization.startswith("Bearer "):
        return error_response("missing_token", "Authorization: Bearer <token> required", 401)
    token = authorization.split(" ", 1)[1]
    try:
        claims = signer.verify_access(token)
    except Exception:
        return error_response("invalid_token", "Access token invalid", 401)
    user = db.query(User).get(int(claims["sub"]))
    if not user:
        return error_response("user_not_found", "User not found", 404)
    return MeResponse(id=user.id, email=user.email, is_active=user.is_active)

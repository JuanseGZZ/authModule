import base64, json, os, secrets, time, datetime as dt
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text, func
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.hash import bcrypt
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# =========================
# Config
# =========================
ACCESS_TOKEN_TTL_SECONDS = 15 * 60       # 15 min
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 días
ISSUER = "https://auth.local"
AUDIENCE = "web|apis"
DB_URL = "sqlite:///./auth.db"

# =========================
# RSA keys (RS256) + JWKS
# =========================
def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def gen_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    now_kid = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return private_key, public_key, now_kid

PRIVATE_KEY, PUBLIC_KEY, KID = gen_rsa_keypair()

PUBLIC_NUMBERS = PUBLIC_KEY.public_numbers()
JWKS = {
    "keys": [{
        "kid": KID,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": b64url_uint(PUBLIC_NUMBERS.n),
        "e": b64url_uint(PUBLIC_NUMBERS.e),
    }]
}

PRIVATE_PEM = PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()
)
PUBLIC_PEM = PUBLIC_KEY.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# =========================
# DB
# =========================
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    refresh_tokens = relationship("RefreshToken", back_populates="user")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)  # opaco
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)       # invalidado manualmente
    used = Column(Boolean, default=False)          # usado para rotación
    replaced_by = Column(String(255), nullable=True)  # token nuevo generado al refrescar

    user = relationship("User", back_populates="refresh_tokens")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# Schemas
# =========================
class RegisterIn(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    username: str
    password: str
    device_info: Optional[str] = None

class RefreshIn(BaseModel):
    refresh_token: str

class TokensOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = ACCESS_TOKEN_TTL_SECONDS

# =========================
# Utils
# =========================
def create_access_token(user: User) -> str:
    now = int(time.time())
    payload = {
        "sub": f"{user.id}",
        "iat": now,
        "nbf": now - 1,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "scope": "read:me",
        "roles": ["user"],
        "kid": KID,  # opcional en payload (estándar es header), pero útil
    }
    token = jwt.encode(payload, PRIVATE_PEM, algorithm="RS256", headers={"kid": KID, "typ": "JWT", "alg": "RS256"})
    return token

def create_refresh_token(db: Session, user: User) -> RefreshToken:
    token = secrets.token_urlsafe(64)  # opaco
    rt = RefreshToken(
        user_id=user.id,
        token=token,
        expires_at=dt.datetime.utcnow() + dt.timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS)
    )
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt

from passlib.hash import argon2

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return argon2.verify(plain, hashed)
    except Exception:
        return False

def hash_password(p: str) -> str:
    return argon2.hash(p)

def require_auth(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return authorization.split(" ", 1)[1].strip()

def decode_access_token(token: str):
    try:
        return jwt.decode(
            token,
            PUBLIC_PEM,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]}
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid access token")

# =========================
# App
# =========================
app = FastAPI(title="Auth JWT Pro (RS256 + Rotation)")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Public Key / JWKS ----------
@app.get("/auth/public-key")
def get_public_key():
    return {"alg": "RS256", "kid": KID, "public_key_pem": PUBLIC_PEM}

@app.get("/.well-known/jwks.json")
def jwks_endpoint():
    return JWKS

# ---------- Register ----------
@app.post("/auth/register", response_model=TokensOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first():
        raise HTTPException(status_code=409, detail="Username or email already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    access = create_access_token(user)
    refresh = create_refresh_token(db, user)
    return TokensOut(access_token=access, refresh_token=refresh.token)

# ---------- Login ----------
@app.post("/auth/login", response_model=TokensOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access = create_access_token(user)
    refresh = create_refresh_token(db, user)
    return TokensOut(access_token=access, refresh_token=refresh.token)

# ---------- Protected (/me) ----------
@app.get("/me")
def me(authorization: Optional[str] = Header(default=None), db: Session = Depends(get_db)):
    token = require_auth(authorization)
    claims = decode_access_token(token)
    user_id = int(claims["sub"])
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "roles": ["user"],
        "data_user": {"first_name": "Emma", "last_name": "Doe"}
    }

# ---------- Refresh (con rotación y un-uso) ----------
@app.post("/auth/refresh", response_model=TokensOut)
def refresh(payload: RefreshIn, db: Session = Depends(get_db)):
    rt: RefreshToken = db.query(RefreshToken).filter(RefreshToken.token == payload.refresh_token).first()
    if not rt:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if rt.revoked:
        raise HTTPException(status_code=403, detail="Refresh token revoked")
    if rt.used:
        # Replay detectado → opcional: revocar todos los refresh del usuario
        raise HTTPException(status_code=409, detail="Refresh token already used (replay detected)")
    if rt.expires_at < dt.datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user = db.query(User).get(rt.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Rotación: marcar viejo como used y generar nuevo
    rt.used = True
    new_rt = create_refresh_token(db, user)
    rt.replaced_by = new_rt.token
    db.add(rt)
    db.commit()

    access = create_access_token(user)
    return TokensOut(access_token=access, refresh_token=new_rt.token)

# ---------- Logout ----------
class LogoutIn(BaseModel):
    refresh_token: str
    all_devices: Optional[bool] = False

@app.post("/auth/logout")
def logout(payload: LogoutIn, db: Session = Depends(get_db)):
    rt = db.query(RefreshToken).filter(RefreshToken.token == payload.refresh_token).first()
    if not rt:
        raise HTTPException(status_code=200, detail="OK")  # idempotente
    if payload.all_devices:
        # Revoca todos los refresh del usuario
        db.query(RefreshToken).filter(
            RefreshToken.user_id == rt.user_id,
            RefreshToken.revoked == False
        ).update({RefreshToken.revoked: True}, synchronize_session=False)
    else:
        rt.revoked = True
        db.add(rt)
    db.commit()
    return {"status": "ok"}

# ---------- Health ----------
@app.get("/healthz")
def health():
    return {"ok": True}

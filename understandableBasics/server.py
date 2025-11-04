# app.py
import os, sqlite3, secrets, hashlib, datetime as dt
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

# === CONFIG ===
ISS = "https://auth.tuapp.com"
AUD = "https://api.tuapp.com"
ACCESS_MINUTES = 15
REFRESH_DAYS = 30
REFRESH_COOKIE = "refresh_token"
ALLOWED_ORIGINS = ["https://tu-frontend.com", "http://localhost:5173", "http://localhost:3000"]

# === CARGA CLAVES RSA (RS256) ===
PRIVATE_KEY = open("private.pem", "r").read()
PUBLIC_KEY = open("public.pem", "r").read()

# === DB SQLITE para refresh tokens (solo almacenamos refresh, no access) ===
DB = "auth.db"
con = sqlite3.connect(DB, check_same_thread=False)
cur = con.cursor()
cur.execute(
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      exp INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    """
)
con.commit()

# === UTILS ===
def now_utc() -> int:
    return int(dt.datetime.utcnow().timestamp())

def hash_refresh(rt: str) -> str:
    return hashlib.sha256(rt.encode()).hexdigest()

def store_refresh(user_id: str, rt: str, exp_secs: int = REFRESH_DAYS * 24 * 3600) -> None:
    cur.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, exp, created_at) VALUES (?,?,?,?)",
        (user_id, hash_refresh(rt), now_utc() + exp_secs, now_utc()),
    )
    con.commit()

def delete_refresh(rt: str) -> None:
    cur.execute("DELETE FROM refresh_tokens WHERE token_hash=?", (hash_refresh(rt),))
    con.commit()

def fetch_refresh(rt: str):
    cur.execute(
        "SELECT user_id, exp FROM refresh_tokens WHERE token_hash=?",
        (hash_refresh(rt),),
    )
    return cur.fetchone()  # (user_id, exp) | None

def gc_expired_refresh():
    cur.execute("DELETE FROM refresh_tokens WHERE exp < ?", (now_utc(),))
    con.commit()


def make_access(user_id: str, minutes: int = ACCESS_MINUTES) -> str:
    iat = dt.datetime.utcnow()
    exp = iat + dt.timedelta(minutes=minutes)
    payload = {
        "iss": ISS,
        "aud": AUD,
        "sub": user_id,
        "iat": iat,
        "exp": exp,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def verify_access(token: str):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISS,
        audience=AUD,
    )


def set_refresh_cookie(resp: Response, rt: str):
    resp.set_cookie(
        key=REFRESH_COOKIE,
        value=rt,
        httponly=True,
        secure=True,
        samesite="Strict",
        path="/auth",
        max_age=REFRESH_DAYS * 24 * 3600,
    )


def clear_refresh_cookie(resp: Response):
    resp.delete_cookie(REFRESH_COOKIE, path="/auth")


# === FASTAPI ===
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(data: LoginIn, response: Response):
    # \u2705 DEMO: acepta cualquier user/pass. En prod, valida contra tu DB.
    user_id = data.username

    access = make_access(user_id)
    refresh = secrets.token_urlsafe(32)  # token opaco
    store_refresh(user_id, refresh)

    set_refresh_cookie(response, refresh)
    return {"access_token": access, "token_type": "Bearer", "sub": user_id}


@app.post("/auth/refresh")
def refresh_token(request: Request, response: Response):
    gc_expired_refresh()
    rt = request.cookies.get(REFRESH_COOKIE)
    if not rt:
        raise HTTPException(401, "Missing refresh token")

    rec = fetch_refresh(rt)
    if not rec:
        raise HTTPException(401, "Invalid refresh token")

    user_id, exp = rec
    if now_utc() > exp:
        delete_refresh(rt)
        raise HTTPException(401, "Expired refresh token")

    # Rotación simple: eliminar el viejo y crear uno nuevo
    delete_refresh(rt)
    new_rt = secrets.token_urlsafe(32)
    store_refresh(user_id, new_rt)

    new_access = make_access(user_id)
    set_refresh_cookie(response, new_rt)
    return {"access_token": new_access, "token_type": "Bearer", "sub": user_id}


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    rt = request.cookies.get(REFRESH_COOKIE)
    if rt:
        delete_refresh(rt)  # \u274c elimina (no revoca) el refresh actual
    clear_refresh_cookie(response)
    return {"detail": "logged out"}


@app.get("/api/secret")
def secret(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    token = auth[7:]
    try:
        payload = verify_access(token)
        return {"ok": True, "you_are": payload["sub"], "jti": payload["jti"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Access expired")
    except Exception:
        raise HTTPException(401, "Invalid access")


# === COMANDOS DE EJECUCI\u00d3N ===
# 1) pip install fastapi uvicorn PyJWT cryptography
# 2) python generate_keys.py  (o crea private.pem/public.pem previamente)
# 3) uvicorn app:app --reload --port 8000
#
# PRUEBA R\u00c1PIDA (bash):
# curl -X POST http://localhost:8000/auth/login -H 'content-type: application/json' \
#   -d '{"username":"juan","password":"x"}' -i
# (copia access_token de la respuesta)
# curl http://localhost:8000/api/secret -H "Authorization: Bearer <ACCESS>"
# curl -X POST http://localhost:8000/auth/refresh -b 'refresh_token=<COOKIE>' -i
# curl -X POST http://localhost:8000/auth/logout -b 'refresh_token=<COOKIE>' -i

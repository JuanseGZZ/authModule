#!/usr/bin/env python3
"""
Single-file FastAPI backend that implements the spec from FRAMEFORK.txt:

- JWT always used.
- Two crypto modes for APIs: stateful (Redis-backed AES per session) and stateless (per-request ECIES-style key transport).
- Handshake endpoint that accepts an AES key encrypted with an elliptic-curve scheme and replies (encrypted with that AES) with:
  - session_id (for stateful mode)
  - access_token (JWT, short TTL)
  - refresh_token (stored server-side for revocation/rotation)
- Register/Login/Refresh/Logout endpoints.
- KMS helpers to create and decrypt per-user keys.

Notes:
- Elliptic curve transport implemented with X25519 + HKDF + AES-GCM (ECIES-like).
- RSA (RS256) is used to SIGN JWTs. The EC key is NOT used to sign tokens.
- Redis is optional; if REDIS_URL is not set or unreachable, an in-memory store is used (for demo/dev).
- All constants/variables have meaningful names.
- Each function has a descriptive docstring above it.

This is a minimal but production-leaning skeleton intended to be extended.
"""

import os
import json
import base64
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

from fastapi import FastAPI, Depends, HTTPException, Request, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Crypto primitives
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

# Optional Redis (fallback to in-memory dict)
try:
    import redis  # type: ignore
except Exception:
    redis = None


# -----------------------------
# Configuration and constants
# -----------------------------

# Security settings and tunables (can be overridden via environment variables)
JWT_ISSUER: str = os.getenv("JWT_ISSUER", "fastapi-framework")
JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "framework-clients")
ACCESS_TOKEN_TTL_SECONDS: int = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))  # 15 min
REFRESH_TOKEN_TTL_SECONDS: int = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", "1209600"))  # 14 days

# API crypto mode: "stateful" or "stateless"
API_CRYPTO_MODE: str = os.getenv("API_CRYPTO_MODE", "stateful").lower()

# Redis URL, e.g., "redis://localhost:6379/0"
REDIS_URL: Optional[str] = os.getenv("REDIS_URL")

# Key file paths (auto-generated if missing)
DATA_DIR = os.getenv("DATA_DIR", ".")
SERVER_EC_PRIVATE_PATH = os.path.join(DATA_DIR, "server_x25519_private.pem")
SERVER_EC_PUBLIC_PATH = os.path.join(DATA_DIR, "server_x25519_public.pem")
JWT_RSA_PRIVATE_PATH = os.path.join(DATA_DIR, "jwt_rsa_private.pem")
JWT_RSA_PUBLIC_PATH = os.path.join(DATA_DIR, "jwt_rsa_public.pem")
KMS_MASTER_KEY_PATH = os.path.join(DATA_DIR, "kms_master.key")

# Session key TTL (only for stateful): 15 minutes as requested
STATEFUL_AES_TTL_SECONDS: int = int(os.getenv("STATEFUL_AES_TTL_SECONDS", "900"))

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("framework-backend")


# -----------------------------
# Utility: Redis-like storage
# -----------------------------

class RedisLikeStorage:
    """Provides a small subset of Redis behavior with TTL support; falls back to in-memory if Redis is not configured."""

    def __init__(self, redis_url: Optional[str]):
        self._is_real_redis = False
        self._r = None
        self._mem: Dict[str, Tuple[bytes, float]] = {}  # key -> (value, expiry_ts)
        if redis_url and redis:
            try:
                self._r = redis.StrictRedis.from_url(redis_url, decode_responses=False)
                # test connection
                self._r.ping()
                self._is_real_redis = True
                logger.info("Connected to Redis.")
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}); using in-memory store.")
        else:
            logger.info("Using in-memory store (Redis not configured).")

    def setex(self, key: str, ttl_seconds: int, value: bytes) -> None:
        """Set a key with TTL."""
        if self._is_real_redis:
            self._r.setex(key, ttl_seconds, value)
        else:
            expiry = datetime.utcnow().timestamp() + ttl_seconds
            self._mem[key] = (value, expiry)

    def get(self, key: str) -> Optional[bytes]:
        """Get a key respecting TTL."""
        if self._is_real_redis:
            value = self._r.get(key)
            return value
        now_ts = datetime.utcnow().timestamp()
        item = self._mem.get(key)
        if not item:
            return None
        value, expiry = item
        if now_ts > expiry:
            self._mem.pop(key, None)
            return None
        return value

    def delete(self, key: str) -> None:
        """Delete a key if exists."""
        if self._is_real_redis:
            self._r.delete(key)
        else:
            self._mem.pop(key, None)


# Initialize storage
storage = RedisLikeStorage(REDIS_URL)


# -----------------------------
# Key management helpers
# -----------------------------

def ensure_server_ec_keypair() -> Tuple[X25519PrivateKey, bytes]:
    """Load or generate server X25519 keypair for ECIES-like transport."""
    if os.path.exists(SERVER_EC_PRIVATE_PATH) and os.path.exists(SERVER_EC_PUBLIC_PATH):
        with open(SERVER_EC_PRIVATE_PATH, "rb") as f:
            private = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_EC_PUBLIC_PATH, "rb") as f:
            server_pub_bytes = f.read()
        return private, server_pub_bytes

    private = X25519PrivateKey.generate()
    public = private.public_key()
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # Save private as PEM (raw wrapped in PKCS8)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(SERVER_EC_PRIVATE_PATH, "wb") as f:
        f.write(private_pem)
    with open(SERVER_EC_PUBLIC_PATH, "wb") as f:
        f.write(pub_bytes)
    logger.info("Generated server X25519 keypair.")
    return private, pub_bytes


def ensure_jwt_rsa_keypair() -> Tuple[bytes, bytes]:
    """Load or generate RSA keypair for JWT RS256 signing."""
    if os.path.exists(JWT_RSA_PRIVATE_PATH) and os.path.exists(JWT_RSA_PUBLIC_PATH):
        with open(JWT_RSA_PRIVATE_PATH, "rb") as f:
            priv = f.read()
        with open(JWT_RSA_PUBLIC_PATH, "rb") as f:
            pub = f.read()
        return priv, pub

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(JWT_RSA_PRIVATE_PATH, "wb") as f:
        f.write(private_pem)
    with open(JWT_RSA_PUBLIC_PATH, "wb") as f:
        f.write(public_pem)
    logger.info("Generated RSA keypair for JWT.")
    return private_pem, public_pem


def ensure_kms_master_key() -> bytes:
    """Load or create the KMS master key (AES-256) used to wrap per-user keys."""
    if os.path.exists(KMS_MASTER_KEY_PATH):
        with open(KMS_MASTER_KEY_PATH, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(KMS_MASTER_KEY_PATH, "wb") as f:
        f.write(key)
    logger.info("Generated KMS master key.")
    return key


SERVER_EC_PRIVATE, SERVER_EC_PUBLIC_BYTES = ensure_server_ec_keypair()
JWT_RSA_PRIVATE_PEM, JWT_RSA_PUBLIC_PEM = ensure_jwt_rsa_keypair()
KMS_MASTER_KEY = ensure_kms_master_key()


# -----------------------------
# Models (basic, to be customized by the app author)
# -----------------------------

class DataPublic(BaseModel):
    """Data visible publicly."""
    bio: Optional[str] = None


class DataPrivate(BaseModel):
    """Sensitive data visible only to specific modules (encrypted with user password)."""
    national_id: Optional[str] = None


class DataProtected(BaseModel):
    """Data visible to modules (encrypted via KMS per-user key)."""
    preferences: Optional[Dict[str, Any]] = None


class UserModel(BaseModel):
    """User entity combining public/private/protected sections."""
    data_public: DataPublic = DataPublic()
    data_private: DataPrivate = DataPrivate()
    data_protected: DataProtected = DataProtected()
    email: str
    username: str
    password_hash: str
    created_at: datetime
    is_admin: bool = False


# In-memory "users" store for demo; replace with a real DB in production.
USERS_DB: Dict[str, UserModel] = {}  # key by username or email


# -----------------------------
# Crypto helpers
# -----------------------------

def hkdf_derive_key(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from an ECDH shared secret using HKDF-SHA256."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)


def ecies_decrypt_aes_key(payload: Dict[str, str]) -> bytes:
    """
    Decrypt the frontend-provided AES key via ECIES-like flow:
      - payload contains base64 fields: 'ephemeral_public_key', 'nonce', 'ciphertext', 'tag'
      - server computes shared secret with its X25519 private key and client's ephemeral public key
      - HKDF derives a transport key; AES-GCM decrypts the AES key
    Returns the raw AES-256 key bytes.
    """
    required = ["ephemeral_public_key", "nonce", "ciphertext", "tag"]
    for field in required:
        if field not in payload:
            raise HTTPException(status_code=400, detail=f"Missing field in EC encrypted payload: {field}")

    client_ephemeral_pub = base64.b64decode(payload["ephemeral_public_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])

    # X25519 shared secret
    client_pub = X25519PublicKey.from_public_bytes(client_ephemeral_pub)
    shared_secret = SERVER_EC_PRIVATE.exchange(client_pub)

    # Derive transport key
    transport_key = hkdf_derive_key(shared_secret, salt=b"ecies-salt", info=b"aes-key-transport", length=32)

    # AES-GCM decrypt
    aesgcm = AESGCM(transport_key)
    decrypted = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)
    if len(decrypted) not in (16, 24, 32):
        raise HTTPException(status_code=400, detail="Invalid AES key length decrypted.")
    return decrypted


def aes_gcm_encrypt(key: bytes, plaintext_obj: Dict[str, Any]) -> Dict[str, str]:
    """Encrypts a JSON-serializable object with AES-GCM and returns base64 fields nonce,ciphertext,tag."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(plaintext_obj, separators=(",", ":")).encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    ciphertext, tag = ct[:-16], ct[-16:]
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def aes_gcm_decrypt(key: bytes, payload: Dict[str, str]) -> Dict[str, Any]:
    """Decrypts AES-GCM payload (nonce,ciphertext,tag base64) into a Python object."""
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)
    return json.loads(pt.decode("utf-8"))


# -----------------------------
# Session/stateful key helpers
# -----------------------------

def generate_session_id() -> str:
    """Generate a URL-safe session identifier."""
    return base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("=")


def put_session_aes(session_id: str, aes_key: bytes) -> None:
    """Store the AES key for a session id with TTL (stateful mode)."""
    storage.setex(f"session:{session_id}:aes", STATEFUL_AES_TTL_SECONDS, aes_key)


def get_session_aes(session_id: str) -> Optional[bytes]:
    """Retrieve the AES key for a session id (returns None if expired/missing)."""
    return storage.get(f"session:{session_id}:aes")


def revoke_session(session_id: str) -> None:
    """Remove session id and its AES key."""
    storage.delete(f"session:{session_id}:aes")


# -----------------------------
# JWT helpers (RS256)
# -----------------------------

def sign_access_token(subject: str, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """Create a short-lived access token (JWT) signed with RS256."""
    now = datetime.utcnow()
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)).timestamp()),
        "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, JWT_RSA_PRIVATE_PEM, algorithm="RS256")
    return token


def mint_and_store_refresh_token(subject: str) -> str:
    """Create a long-lived refresh token (opaque random) and store it with TTL."""
    refresh_token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    storage.setex(f"refresh:{refresh_token}", REFRESH_TOKEN_TTL_SECONDS, subject.encode("utf-8"))
    return refresh_token


def revoke_refresh_token(refresh_token: str) -> None:
    """Revoke a refresh token immediately."""
    storage.delete(f"refresh:{refresh_token}")


def validate_refresh_token(refresh_token: str) -> Optional[str]:
    """Return subject if refresh token is valid and not expired."""
    value = storage.get(f"refresh:{refresh_token}")
    return value.decode("utf-8") if value else None


# -----------------------------
# KMS (key management service)
# -----------------------------

def kms_encrypt_with_master(plaintext_key: bytes) -> str:
    """
    Encrypt a per-user key with the KMS master key using AES-GCM.
    Returns base64 of nonce|ciphertext|tag as a JSON object string.
    """
    aesgcm = AESGCM(KMS_MASTER_KEY)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext_key, None)
    payload = {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct[:-16]).decode(),
        "tag": base64.b64encode(ct[-16:]).decode(),
    }
    return json.dumps(payload)


def kms_decrypt_with_master(encrypted_payload_json: str) -> bytes:
    """Decrypt a base64 JSON (nonce,ciphertext,tag) with the KMS master key and return raw bytes."""
    payload = json.loads(encrypted_payload_json)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])
    aesgcm = AESGCM(KMS_MASTER_KEY)
    key_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return key_bytes


def crear_key_user() -> Dict[str, str]:
    """Create a random per-user AES-256 key and return plaintext (base64) and encrypted (JSON string)."""
    user_key = secrets.token_bytes(32)
    encrypted = kms_encrypt_with_master(user_key)
    return {
        "plaintext_base64": base64.b64encode(user_key).decode(),
        "encrypted_json": encrypted,
    }


def decifrar_key(encrypted_json: str) -> str:
    """Decrypt an encrypted per-user key JSON and return the plaintext base64 string."""
    key_bytes = kms_decrypt_with_master(encrypted_json)
    return base64.b64encode(key_bytes).decode()


# -----------------------------
# API payload schemas
# -----------------------------

class ECEncryptedKeyEnvelope(BaseModel):
    ephemeral_public_key: str
    nonce: str
    ciphertext: str
    tag: str


class HandshakeRequest(BaseModel):
    ec_encrypted: ECEncryptedKeyEnvelope


class EncryptedBody(BaseModel):
    # Generic AES-GCM envelope used for API payloads
    nonce: str
    ciphertext: str
    tag: str
    # For stateful mode, client also sends session_id beside the envelope
    session_id: Optional[str] = None


class RegisterPayload(BaseModel):
    email: str
    username: str
    password: str


class LoginPayload(BaseModel):
    username_or_email: str
    password: str


class RefreshPayload(BaseModel):
    refresh_token: str


# -----------------------------
# FastAPI app
# -----------------------------

app = FastAPI(title="Framework Backend", version="0.1.0")


# -----------------------------
# Crypto mode utilities
# -----------------------------

def descifrado_state_less(enc_body: EncryptedBody) -> Dict[str, Any]:
    """
    Stateless decryption:
      - Expects the request to include an EC-encrypted AES key envelope in headers 'X-EC-Envelope' (base64 JSON).
      - Decrypt that AES key and then AES-GCM decrypt the body.
    """
    # The frontend supplies the EC envelope via header as a base64-encoded JSON string.
    from fastapi import Header
    raise HTTPException(status_code=400, detail="descifrado_state_less must be called via dependency.")


async def get_request_context(request: Request) -> Dict[str, Any]:
    """
    Extract context needed for crypto flows:
      - In stateless mode: read 'x-ec-envelope' header (base64-encoded JSON with EC envelope).
      - In stateful mode: 'session_id' inside body is used.
    """
    headers = {k.lower(): v for k, v in request.headers.items()}
    ec_envelope_b64 = headers.get("x-ec-envelope")
    return {
        "ec_envelope_b64": ec_envelope_b64,
    }


# -----------------------------
# Endpoint: /.well-known/server-keys
# -----------------------------

@app.get("/.well-known/server-keys")
def get_server_keys():
    """Expose server public keys needed by the frontend: EC public (raw) and JWT RSA public (PEM)."""
    return {
        "ec_curve": "X25519",
        "ec_public_key_base64": base64.b64encode(SERVER_EC_PUBLIC_BYTES).decode(),
        "jwt_alg": "RS256",
        "jwt_rsa_public_pem": JWT_RSA_PUBLIC_PEM.decode(),
    }


# -----------------------------
# Endpoint: /api/handshake
# -----------------------------

@app.post("/api/handshake")
def api_handshake(req: HandshakeRequest):
    """
    Handshake:
      - Decrypt the AES key that the frontend generated (via ECIES-like envelope).
      - Create a session_id and store (session_id -> AES) with TTL (stateful).
      - Mint access and refresh tokens.
      - Respond with {session_id, access_token, refresh_token} encrypted with the client's AES key.
    """
    try:
        aes_key = ecies_decrypt_aes_key(req.ec_encrypted.dict())
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Handshake EC decrypt failed.")
        raise HTTPException(status_code=400, detail=f"EC decrypt failed: {str(e)}")

    session_id = generate_session_id()
    put_session_aes(session_id, aes_key)

    access_token = sign_access_token(subject=session_id, extra_claims={"mode": API_CRYPTO_MODE})
    refresh_token = mint_and_store_refresh_token(subject=session_id)

    response_plain = {
        "session_id": session_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }
    encrypted = aes_gcm_encrypt(aes_key, response_plain)
    return encrypted


# -----------------------------
# Core decrypt/encrypt helpers for APIs
# -----------------------------

def descifrado_statefull_request(body: EncryptedBody) -> Dict[str, Any]:
    """
    Decrypt an API request in stateful mode:
      - Uses the session_id to fetch AES from Redis and decrypts the AES-GCM envelope in the body.
    """
    if not body.session_id:
        raise HTTPException(status_code=400, detail="Missing session_id for stateful mode.")
    aes_key = get_session_aes(body.session_id)
    if not aes_key:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    try:
        payload = aes_gcm_decrypt(aes_key, body.dict())
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Stateful decrypt failed: {str(e)}")


def cifrado_statefull_response(session_id: str, payload_obj: Dict[str, Any]) -> Dict[str, str]:
    """
    Encrypt an API response in stateful mode using the stored AES key for the session_id.
    """
    aes_key = get_session_aes(session_id)
    if not aes_key:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return aes_gcm_encrypt(aes_key, payload_obj)


def descifrado_stateless_request(request: Request, body: EncryptedBody, ctx: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
    """
    Decrypt an API request in stateless mode:
      - Read 'X-EC-Envelope' header (base64 JSON).
      - Decrypt AES key via ECIES-like method.
      - Decrypt AES-GCM envelope in body.
      - Return (aes_key, payload_obj).
    """
    ec_b64 = ctx.get("ec_envelope_b64")
    if not ec_b64:
        raise HTTPException(status_code=400, detail="Missing X-EC-Envelope header for stateless mode.")
    try:
        envelope_json = base64.b64decode(ec_b64).decode()
        envelope = json.loads(envelope_json)
        aes_key = ecies_decrypt_aes_key(envelope)
        payload_obj = aes_gcm_decrypt(aes_key, body.dict())
        return aes_key, payload_obj
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Stateless decrypt failed: {str(e)}")


def cifrado_stateless_response(aes_key: bytes, payload_obj: Dict[str, Any]) -> Dict[str, str]:
    """
    Encrypt an API response in stateless mode using the per-request AES key.
    """
    return aes_gcm_encrypt(aes_key, payload_obj)


# -----------------------------
# Endpoint: /register
# -----------------------------

@app.post("/register")
async def register(request: Request, enc: EncryptedBody = Body(...)):
    """
    Register a new user.
      - Decrypts the incoming payload per configured API_CRYPTO_MODE.
      - Creates the user and returns {access_token, refresh_token} encrypted via cifradoStateFull().
    """
    ctx = await get_request_context(request)
    if API_CRYPTO_MODE == "stateless":
        aes_key, payload_obj = descifrado_stateless_request(request, enc, ctx)
        session_id = None
    else:
        payload_obj = descifrado_statefull_request(enc)
        session_id = enc.session_id

    try:
        data = RegisterPayload(**payload_obj)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid register payload.")

    if data.username in USERS_DB or any(u.email == data.email for u in USERS_DB.values()):
        raise HTTPException(status_code=409, detail="User already exists.")

    password_hash = hashlib.sha256(data.password.encode()).hexdigest()
    user = UserModel(
        email=data.email,
        username=data.username,
        password_hash=password_hash,
        created_at=datetime.utcnow(),
        is_admin=False,
    )
    USERS_DB[data.username] = user

    # Ensure we have a stateful session to encrypt response
    if API_CRYPTO_MODE == "stateless":
        # Create session from this request's AES key so subsequent calls can be stateful
        session_id = generate_session_id()
        put_session_aes(session_id, aes_key)

    access_token = sign_access_token(subject=session_id, extra_claims={"username": data.username})
    refresh_token = mint_and_store_refresh_token(subject=session_id)

    response_obj = {"access_token": access_token, "refresh_token": refresh_token, "username": data.username}
    return cifrado_statefull_response(session_id, response_obj)


# -----------------------------
# Endpoint: /login
# -----------------------------

@app.post("/login")
async def login(request: Request, enc: EncryptedBody = Body(...)):
    """
    Log in an existing user.
      - Decrypts the incoming payload per configured API_CRYPTO_MODE.
      - Issues new access/refresh tokens and returns them encrypted via cifradoStateFull().
    """
    ctx = await get_request_context(request)
    if API_CRYPTO_MODE == "stateless":
        aes_key, payload_obj = descifrado_stateless_request(request, enc, ctx)
        session_id = None
    else:
        payload_obj = descifrado_statefull_request(enc)
        session_id = enc.session_id

    try:
        data = LoginPayload(**payload_obj)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid login payload.")

    # Locate user by username or email
    user: Optional[UserModel] = None
    if data.username_or_email in USERS_DB:
        user = USERS_DB[data.username_or_email]
    else:
        for u in USERS_DB.values():
            if u.email == data.username_or_email:
                user = u
                break
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    password_hash = hashlib.sha256(data.password.encode()).hexdigest()
    if user.password_hash != password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    if API_CRYPTO_MODE == "stateless":
        session_id = generate_session_id()
        put_session_aes(session_id, aes_key)

    access_token = sign_access_token(subject=session_id, extra_claims={"username": user.username})
    refresh_token = mint_and_store_refresh_token(subject=session_id)

    response_obj = {"access_token": access_token, "refresh_token": refresh_token, "username": user.username}
    return cifrado_statefull_response(session_id, response_obj)


# -----------------------------
# Endpoint: /refresh
# -----------------------------

@app.post("/refresh")
async def refresh_token_endpoint(request: Request, enc: EncryptedBody = Body(...)):
    """
    Refresh the access token using a valid refresh token (stored server-side).
      - Decrypts request via configured mode.
      - Issues a new access token; returns encrypted via cifradoStateFull().
    """
    ctx = await get_request_context(request)
    if API_CRYPTO_MODE == "stateless":
        aes_key, payload_obj = descifrado_stateless_request(request, enc, ctx)
        session_id = None
    else:
        payload_obj = descifrado_statefull_request(enc)
        session_id = enc.session_id

    try:
        data = RefreshPayload(**payload_obj)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid refresh payload.")

    subject = validate_refresh_token(data.refresh_token)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")
    # Subject is the session_id
    new_access = sign_access_token(subject=subject)
    response_obj = {"access_token": new_access}
    # For stateless calls, ensure we have a session for response encryption
    if API_CRYPTO_MODE == "stateless":
        if not session_id:
            session_id = subject
            aes_key_state = get_session_aes(session_id)
            if not aes_key_state:
                # Can't encrypt stateful response; fall back to stateless response
                return cifrado_stateless_response(aes_key, response_obj)
    return cifrado_statefull_response(session_id, response_obj)


# -----------------------------
# Endpoint: /logout
# -----------------------------

@app.post("/logout")
async def logout(request: Request, enc: EncryptedBody = Body(...)):
    """
    Logout:
      - Decrypt per configured mode.
      - Revoke refresh token and/or session_id (stateful).
      - Reply 'ok' encrypted with cifradoStateFull().
    """
    ctx = await get_request_context(request)
    if API_CRYPTO_MODE == "stateless":
        aes_key, payload_obj = descifrado_stateless_request(request, enc, ctx)
        session_id = None
    else:
        payload_obj = descifrado_statefull_request(enc)
        session_id = enc.session_id

    refresh_token = payload_obj.get("refresh_token")
    if refresh_token:
        revoke_refresh_token(refresh_token)

    if session_id:
        revoke_session(session_id)

    response_obj = {"status": "ok"}
    if API_CRYPTO_MODE == "stateless":
        # If no state, reply using the same per-request AES
        return cifrado_stateless_response(aes_key, response_obj)
    return cifrado_statefull_response(session_id, response_obj)


# -----------------------------
# Example protected API: /echo
# -----------------------------

@app.post("/echo")
async def echo(request: Request, enc: EncryptedBody = Body(...)):
    """
    Example protected endpoint that:
      - Decrypts the incoming payload per configured mode.
      - Returns the same content plus 'echoed_at' timestamp, encrypted appropriately.
    """
    ctx = await get_request_context(request)
    if API_CRYPTO_MODE == "stateless":
        aes_key, payload_obj = descifrado_stateless_request(request, enc, ctx)
        payload_obj["echoed_at"] = datetime.utcnow().isoformat() + "Z"
        return cifrado_stateless_response(aes_key, payload_obj)
    else:
        payload_obj = descifrado_statefull_request(enc)
        payload_obj["echoed_at"] = datetime.utcnow().isoformat() + "Z"
        return cifrado_statefull_response(enc.session_id, payload_obj)


# -----------------------------
# KMS endpoints
# -----------------------------

@app.post("/kms/crearKeyUser")
def kms_crear_key_user():
    """Create a per-user key; returns both plaintext (base64) and encrypted (JSON string)."""
    return crear_key_user()


class KMSDecryptRequest(BaseModel):
    encrypted_json: str


@app.post("/kms/decifrarKey")
def kms_decifrar_key(req: KMSDecryptRequest):
    """Decrypt a previously KMS-encrypted per-user key and return the plaintext base64."""
    return {"plaintext_base64": decifrar_key(req.encrypted_json)}


# -----------------------------
# Health
# -----------------------------

@app.get("/healthz")
def healthz():
    """Simple health endpoint."""
    return {"status": "ok", "mode": API_CRYPTO_MODE}


# -----------------------------
# Main
# -----------------------------
from fastapi.middleware.cors import CORSMiddleware

allowed_origins = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        # agregá otros orígenes si usás otro puerto/host
    ]

app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["*"],
        allow_headers=["Content-Type", "Authorization", "X-EC-Envelope"],
        expose_headers=["*"],
        allow_credentials=False,
    )

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)

# server.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict
import base64, json, os, uuid, pathlib, binascii, time

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- CONFIG ----------------
BASE_DIR = pathlib.Path(__file__).resolve().parent
PRIVATE_PEM = BASE_DIR / "private.pem"
PUBLIC_PEM  = BASE_DIR / "public.pem"

if not PRIVATE_PEM.exists() or not PUBLIC_PEM.exists():
    raise RuntimeError("Faltan private.pem o public.pem junto a server.py")

with open(PRIVATE_PEM, "rb") as f:
    _backend_private_key = load_pem_private_key(f.read(), password=None)

with open(PUBLIC_PEM, "rb") as f:
    _backend_public_pem_bytes = f.read()

try:
    _backend_public = load_pem_public_key(_backend_public_pem_bytes)
    _backend_public_spki_pem = _backend_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
except Exception:
    _backend_public_spki_pem = _backend_public_pem_bytes

def backend_public_spki_pem_b64() -> str:
    return base64.b64encode(_backend_public_spki_pem).decode()

# ---- sessions store (in-memory) ----
_sessions: Dict[str, bytes] = {}

# ---------------- MODELS ----------------
class HandshakeStartIn(BaseModel):
    # Client sends an RSA-encrypted blob containing {aes_key_b64, nonce_b64}
    rsa_ct_b64: str

class HandshakeStartOut(BaseModel):
    iv_b64: str
    ciphertext_b64: str
    debug_server_plain_b64: str
    debug_aes_key_b64: str
    session_id: str

class EncryptedIn(BaseModel):
    session_id: str
    iv_b64: str
    ciphertext_b64: str

class EncryptedOut(BaseModel):
    iv_b64: str
    ciphertext_b64: str
    debug_server_received_plain_b64: str
    debug_server_reply_plain_b64: str

# ---------------- APP ----------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # restringir en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/getKeyPublic")
def get_key_public():
    """Return server public key (SPKI PEM) encoded as base64 so front can import it."""
    return {"backend_public_spki_pem_b64": backend_public_spki_pem_b64()}

@app.post("/handshake/start", response_model=HandshakeStartOut)
def handshake_start(body: HandshakeStartIn):
    start_t = time.time()
    # 1) RSA decrypt using server private key (we expect a small JSON with AES key)
    try:
        rsa_ct = base64.b64decode(body.rsa_ct_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 rsa_ct_b64: {e}")

    print("\n----- SERVER: HANDSHAKE START -----")
    print("Received RSA CT (b64) len:", len(body.rsa_ct_b64))
    print("RSA CT (hex, first 120 chars):", binascii.hexlify(rsa_ct)[:120].decode() + " ...")

    try:
        plaintext = _backend_private_key.decrypt(
            rsa_ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
    except Exception as e:
        print("RSA decrypt error:", e)
        raise HTTPException(status_code=400, detail=f"RSA decrypt error: {e}")

    print("RSA decrypted bytes len:", len(plaintext))
    print("RSA decrypted (raw bytes hex, first 120):", binascii.hexlify(plaintext)[:120].decode() + " ...")
    try:
        parsed = json.loads(plaintext.decode())
    except Exception as e:
        print("Failed to parse JSON from RSA plaintext:", e)
        raise HTTPException(status_code=400, detail=f"Invalid RSA payload JSON: {e}")

    aes_key_b64 = parsed.get("aes_key_b64")
    nonce_b64 = parsed.get("nonce_b64")

    print("Parsed from RSA JSON keys:", list(parsed.keys()))
    print("aes_key_b64 (len):", len(aes_key_b64) if aes_key_b64 else None)
    print("nonce_b64 (len):", len(nonce_b64) if nonce_b64 else None)

    try:
        aes_key = base64.b64decode(aes_key_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 aes_key_b64: {e}")

    if len(aes_key) not in (16,24,32):
        raise HTTPException(status_code=400, detail="AES key length invalid (must be 16/24/32 bytes)")

    # 2) create session and store AES key
    session_id = str(uuid.uuid4())
    _sessions[session_id] = aes_key

    # 3) prepare response JSON and encrypt with AES-GCM (using the AES provided by client)
    response_obj = {
        "session_id": session_id,
        "nonce_echo": nonce_b64,
        "alg": "AES-GCM",
        "iv_len": 12
    }
    response_bytes = json.dumps(response_obj).encode()

    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ct_out = aesgcm.encrypt(iv, response_bytes, associated_data=None)

    # debug values (b64)
    iv_b64 = base64.b64encode(iv).decode()
    ct_out_b64 = base64.b64encode(ct_out).decode()
    debug_plain_b64 = base64.b64encode(plaintext).decode()
    debug_aes_key_b64 = base64.b64encode(aes_key).decode()

    print("Session created:", session_id)
    print("Response plaintext JSON:", response_obj)
    print("Response IV (b64):", iv_b64)
    print("Response CT (b64 len):", len(ct_out_b64))
    print("Response CT (hex first 120):", binascii.hexlify(ct_out)[:120].decode() + " ...")
    print("----- END HANDSHAKE (took %.3fs) -----\n" % (time.time()-start_t))

    return HandshakeStartOut(
        iv_b64=iv_b64,
        ciphertext_b64=ct_out_b64,
        debug_server_plain_b64=debug_plain_b64,
        debug_aes_key_b64=debug_aes_key_b64,
        session_id=session_id
    )

@app.post("/secure/echo", response_model=EncryptedOut)
def secure_echo(body: EncryptedIn):
    t0 = time.time()
    print("\n----- SERVER: SECURE ECHO -----")
    session_id = body.session_id
    aes_key = _sessions.get(session_id)
    if not aes_key:
        print("Invalid session id:", session_id)
        raise HTTPException(status_code=401, detail="Invalid session_id")

    print("Session id:", session_id)
    print("AES key (b64):", base64.b64encode(aes_key).decode())

    try:
        iv = base64.b64decode(body.iv_b64)
        ct = base64.b64decode(body.ciphertext_b64)
    except Exception as e:
        print("Base64 decode error:", e)
        raise HTTPException(status_code=400, detail=f"Invalid base64 in iv/ciphertext: {e}")

    print("Received IV (b64):", body.iv_b64)
    print("Received CT (b64 len):", len(body.ciphertext_b64))
    print("Received CT (hex first 120):", binascii.hexlify(ct)[:120].decode() + " ...")

    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(iv, ct, associated_data=None)
    except Exception as e:
        print("AES decrypt error:", e)
        raise HTTPException(status_code=400, detail=f"AES decrypt error: {e}")

    print("Decrypted plaintext (utf8):", plaintext.decode(errors="replace"))
    print("Decrypted plaintext (b64):", base64.b64encode(plaintext).decode())

    # prepare reply
    reply_plain = ("BACK ECHO: " + plaintext.decode()).encode()
    iv2 = os.urandom(12)
    ct2 = aesgcm.encrypt(iv2, reply_plain, associated_data=None)

    iv2_b64 = base64.b64encode(iv2).decode()
    ct2_b64 = base64.b64encode(ct2).decode()

    print("Reply plaintext (utf8):", reply_plain.decode())
    print("Reply plaintext (b64):", base64.b64encode(reply_plain).decode())
    print("Reply IV (b64):", iv2_b64)
    print("Reply CT (b64 len):", len(ct2_b64))
    print("Reply CT (hex first 120):", binascii.hexlify(ct2)[:120].decode() + " ...")
    print("----- END SECURE ECHO (took %.3fs) -----\n" % (time.time()-t0))

    return EncryptedOut(
        iv_b64=iv2_b64,
        ciphertext_b64=ct2_b64,
        debug_server_received_plain_b64=base64.b64encode(plaintext).decode(),
        debug_server_reply_plain_b64=base64.b64encode(reply_plain).decode()
    )

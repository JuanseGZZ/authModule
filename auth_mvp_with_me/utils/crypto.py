
# Criptografía mínima para MVP: JWS RS256 + JWE nested (RSA-OAEP/AESGCM)
# NOTA: En producción usar librerías maduras (jose/jwt, jwcrypto) y KMS. Este es un helper mínimo.
import os, json, base64, time, hashlib, uuid
from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import constant_time
from bcrypt import hashpw, gensalt, checkpw

# --- Key management (MVP: genera si no existen). TODO: integrar KMS y rotación según YAML.
_state = {"keys": None}

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def _b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def get_keys() -> Dict[str, Any]:
    global _state
    if _state["keys"] is not None:
        return _state["keys"]
    # Sign key (RSA)
    sig_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_front_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def to_jwk(priv, use, kid):
        pub = priv.public_key()
        numbers = pub.public_numbers()
        jwk = {
            "kty": "RSA",
            "use": use,
            "kid": kid,
            "alg": "RS256" if use=="sig" else "RSA-OAEP-256",
            "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length()+7)//8, "big")),
            "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length()+7)//8, "big")),
        }
        return jwk
    keys = {
        "sig": {"priv": sig_key, "public_jwk": to_jwk(sig_key, "sig", "sig-ephemeral"), "kid": "sig-ephemeral"},
        "enc": {"priv": enc_key, "public_jwk": to_jwk(enc_key, "enc", "enc-ephemeral"), "kid": "enc-ephemeral"},
        "enc_front": {"priv": enc_front_key, "public_jwk": to_jwk(enc_front_key, "enc", "enc-front-ephemeral"), "kid": "enc-front-ephemeral"},
    }
    _state["keys"] = keys
    return keys

# --- Passwords
def hash_password(password: str) -> bytes:
    return hashpw(password.encode("utf-8"), gensalt())

def verify_password(password: str, password_hash: bytes) -> bool:
    try:
        return checkpw(password.encode("utf-8"), password_hash)
    except Exception:
        return False

# --- JWS (RS256)
def sign_jws(payload: Dict[str, Any]) -> str:
    keys = get_keys()
    header = {"alg": "RS256", "typ": "JWT", "kid": keys["sig"]["kid"]}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = (header_b64 + "." + payload_b64).encode("utf-8")
    signature = keys["sig"]["priv"].sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return header_b64 + "." + payload_b64 + "." + _b64url(signature)

# --- JWE nested: cifra el JWS anterior (compact) con RSA-OAEP-256 + AESGCM
def _rsa_encrypt(pubkey, data: bytes) -> bytes:
    return pubkey.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def _rsa_decrypt(privkey, data: bytes) -> bytes:
    return privkey.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_jwe_nested(jws_compact: str) -> str:
    keys = get_keys()
    # content encryption key (CEK)
    cek = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    aes = AESGCM(cek)
    ciphertext = aes.encrypt(iv, jws_compact.encode("utf-8"), None)
    # encrypt CEK with RSA enc key
    enc_key_pub = keys["enc"]["priv"].public_key()
    cek_encrypted = _rsa_encrypt(enc_key_pub, cek)
    # pack compact-ish
    parts = [
        _b64url(json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": keys["enc"]["kid"]}).encode()),
        _b64url(cek_encrypted),
        _b64url(iv),
        _b64url(ciphertext[:-16]),  # ciphertext without tag
        _b64url(ciphertext[-16:])   # tag
    ]
    return ".".join(parts)

def decrypt_front_jwe(jwe_compact: str):
    # Para descifrar payloads del front con la clave enc_front
    keys = get_keys()
    h_b64, cek_b64, iv_b64, ct_b64, tag_b64 = jwe_compact.split(".")
    cek = _rsa_decrypt(keys["enc_front"]["priv"], _b64url_decode(cek_b64))
    aes = AESGCM(cek)
    iv = _b64url_decode(iv_b64)
    ct = _b64url_decode(ct_b64) + _b64url_decode(tag_b64)
    data = aes.decrypt(iv, ct, None)
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


# --- Decrypt nested JWE and verify inner JWS
def decrypt_jwe_nested(jwe_compact: str) -> str:
    # returns the inner JWS compact string
    h_b64, cek_b64, iv_b64, ct_b64, tag_b64 = jwe_compact.split(".")
    keys = get_keys()
    cek = _rsa_decrypt(keys["enc"]["priv"], _b64url_decode(cek_b64))
    aes = AESGCM(cek)
    iv = _b64url_decode(iv_b64)
    ct = _b64url_decode(ct_b64) + _b64url_decode(tag_b64)
    data = aes.decrypt(iv, ct, None)
    return data.decode("utf-8")

def verify_jws(jws_compact: str) -> dict:
    # verify RS256 signature and return payload dict (no audience/nonce checks in MVP)
    header_b64, payload_b64, sig_b64 = jws_compact.split(".")
    header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    keys = get_keys()
    pub = keys["sig"]["priv"].public_key()
    signing_input = (header_b64 + "." + payload_b64).encode("utf-8")
    try:
        pub.verify(_b64url_decode(sig_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise ValueError("Firma inválida")
    return json.loads(_b64url_decode(payload_b64).decode("utf-8"))

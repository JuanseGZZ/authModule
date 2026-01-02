import os, json, base64
from typing import Any, Dict, Tuple, Optional
from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

def _stripq(s: str) -> str:
    return (s or "").strip().strip('"').strip("'")

def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1","true","yes","y","on")

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def kms_pub_path() -> str:
    return _stripq(os.getenv("KMS_KEY_PATH_PUB", ""))

def kms_priv_path() -> str:
    return _stripq(os.getenv("KMS_KEY_PATH_PRI", ""))

def ensure_kms_rsa_keys_once(key_size: int = 2048) -> Dict[str, str]:
    if not env_bool("KMS_IS_IT_INSTANCE", False):
        raise RuntimeError("ensure_kms_rsa_keys_once solo en instancia KMS")

    pub_p = kms_pub_path()
    pri_p = kms_priv_path()
    if not pub_p or not pri_p:
        raise RuntimeError("Faltan KMS_KEY_PATH_PUB/KMS_KEY_PATH_PRI")

    os.makedirs(os.path.dirname(pub_p) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(pri_p) or ".", exist_ok=True)

    if os.path.exists(pub_p) and os.path.exists(pri_p):
        return {"pub": pub_p, "pri": pri_p}

    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    pri_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(pri_p, "wb") as f:
        f.write(pri_bytes)
    with open(pub_p, "wb") as f:
        f.write(pub_bytes)

    return {"pub": pub_p, "pri": pri_p}

def load_kms_pubkey():
    p = kms_pub_path()
    if not p:
        raise RuntimeError("KMS_KEY_PATH_PUB vacio")
    with open(p, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_kms_privkey():
    p = kms_priv_path()
    if not p:
        raise RuntimeError("KMS_KEY_PATH_PRI vacio")
    with open(p, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def rsa_oaep_encrypt(pubkey, data: bytes) -> bytes:
    return pubkey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_oaep_decrypt(privkey, data: bytes) -> bytes:
    return privkey.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def aesgcm_encrypt_json(key: bytes, payload: Dict[str, Any]) -> Dict[str, str]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    pt = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = aes.encrypt(nonce, pt, None)
    return {"nonce_b64": b64e(nonce), "ct_b64": b64e(ct)}

def aesgcm_decrypt_json(key: bytes, nonce_b64: str, ct_b64: str) -> Dict[str, Any]:
    aes = AESGCM(key)
    nonce = b64d(nonce_b64)
    ct = b64d(ct_b64)
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

def pack_hybrid(kms_pubkey, payload: Dict[str, Any]) -> Tuple[Dict[str, str], bytes]:
    sess_key = os.urandom(32)
    enc = aesgcm_encrypt_json(sess_key, payload)
    ek = rsa_oaep_encrypt(kms_pubkey, sess_key)
    env = {"ek_b64": b64e(ek), "nonce_b64": enc["nonce_b64"], "ct_b64": enc["ct_b64"]}
    return env, sess_key

def unpack_hybrid(kms_privkey, envelope: Dict[str, str]) -> Tuple[Dict[str, Any], bytes]:
    sess_key = rsa_oaep_decrypt(kms_privkey, b64d(envelope["ek_b64"]))
    obj = aesgcm_decrypt_json(sess_key, envelope["nonce_b64"], envelope["ct_b64"])
    return obj, sess_key

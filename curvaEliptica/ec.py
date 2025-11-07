from __future__ import annotations
import base64, os, json
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dotenv import load_dotenv, set_key, find_dotenv

ENV_PRIV = "ECC_X25519_PRIV"
ENV_PUB  = "ECC_X25519_PUB"

@dataclass
class ECCKeypair:
    priv: x25519.X25519PrivateKey
    pub:  x25519.X25519PublicKey

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def ensure_keys_in_env() -> ECCKeypair:
    env_path = find_dotenv(usecwd=True) or os.path.join(os.getcwd(), ".env")
    load_dotenv(env_path)

    priv_b64 = os.getenv(ENV_PRIV)
    pub_b64  = os.getenv(ENV_PUB)

    if priv_b64 and pub_b64:
        priv = x25519.X25519PrivateKey.from_private_bytes(b64d(priv_b64))
        pub  = x25519.X25519PublicKey.from_public_bytes(b64d(pub_b64))
        return ECCKeypair(priv, pub)

    # Generar nuevas claves
    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key()

    # ✅ Usar métodos RAW correctos
    priv_raw = priv.private_bytes_raw()
    pub_raw  = pub.public_bytes_raw()

    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    if not os.path.exists(env_path):
        open(env_path, "a").close()

    set_key(env_path, ENV_PRIV, b64e(priv_raw))
    set_key(env_path, ENV_PUB,  b64e(pub_raw))

    return ECCKeypair(priv, pub)

def derive_aead_key(shared_secret: bytes, info: bytes = b"ecies-x25519-aesgcm") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)

def encrypt_with_recipient_pub(recipient_pub: x25519.X25519PublicKey, plaintext: bytes, aad: bytes = b"") -> dict:
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()
    shared = eph_priv.exchange(recipient_pub)
    aead_key = derive_aead_key(shared)

    aesgcm = AESGCM(aead_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)

    return {
        "ephemeral_pub": b64e(eph_pub.public_bytes_raw()),
        "nonce":         b64e(nonce),
        "ciphertext":    b64e(ct),
        "aad":           b64e(aad) if aad else "",
        "scheme":        "ECIES-X25519-AESGCM-HKDF-SHA256"
    }

def decrypt_with_recipient_priv(recipient_priv: x25519.X25519PrivateKey, packet: dict) -> bytes:
    eph_pub = x25519.X25519PublicKey.from_public_bytes(b64d(packet["ephemeral_pub"]))
    nonce   = b64d(packet["nonce"])
    ct      = b64d(packet["ciphertext"])
    aad     = b64d(packet["aad"]) if packet.get("aad") else None

    shared = recipient_priv.exchange(eph_pub)
    aead_key = derive_aead_key(shared)
    aesgcm = AESGCM(aead_key)
    return aesgcm.decrypt(nonce, ct, aad)

def demo():
    print("== Asegurando claves en .env ==")
    kp = ensure_keys_in_env()
    print("Pública (Base64):", b64e(kp.pub.public_bytes_raw()))
    print("Privada (Base64):", b64e(kp.priv.private_bytes_raw()))

    mensaje = b"hola mundo cifrado con X25519 + AES-GCM"
    aad = b"opcional-AAD"
    print(mensaje)

    print("\n== Cifrar ==")
    packet = encrypt_with_recipient_pub(kp.pub, mensaje, aad=aad)
    print(json.dumps(packet, indent=2))

    print("\n== Descifrar ==")
    recovered = decrypt_with_recipient_priv(kp.priv, packet)
    print("Recuperado:", recovered.decode("utf-8"))

if __name__ == "__main__":
    demo()

# utils/keys.py
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Mapping, Optional

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

class KeyPaths:
    """Strongly-typed container for key file paths."""
    def __init__(
        self,
        ec_priv: Path,
        ec_pub: Path,
        rsa_priv: Path,
        rsa_pub: Path,
        aes_key: Path,
        aes_mode: str,
    ) -> None:
        self.ec_priv = ec_priv
        self.ec_pub = ec_pub
        self.rsa_priv = rsa_priv
        self.rsa_pub = rsa_pub
        self.aes_key = aes_key
        self.aes_mode = aes_mode

def _get_env_path(name: str, default: Optional[str] = None) -> Path:
    val = os.getenv(name, default)
    if not val:
        raise ValueError(f"Missing required env var: {name}")
    return Path(val).expanduser().resolve()

def _chmod_owner_readwrite(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception:
        pass

def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    _chmod_owner_readwrite(path)

def _serialize_private_key_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

def _serialize_public_key_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

def _ensure_ec_keypair(priv_path: Path, pub_path: Path) -> None:
    """
    NOTE: Aunque el nombre se mantenga por compatibilidad,
    ahora genera **otra** clave RSA (3072) en las rutas EC_ENC_*.
    """
    _ensure_parent_dir(priv_path)
    _ensure_parent_dir(pub_path)

    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not pub_path.exists():
            pub_pem = _serialize_public_key_pem(priv.public_key())
            _atomic_write_bytes(pub_path, pub_pem)
        return

    # Nueva política: usar RSA 3072 también para el par "EC_ENC_*"
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = _serialize_private_key_pem(priv)
    pub_pem = _serialize_public_key_pem(priv.public_key())

    _atomic_write_bytes(priv_path, priv_pem)
    _atomic_write_bytes(pub_path, pub_pem)

def _ensure_rsa_keypair(priv_path: Path, pub_path: Path) -> None:
    _ensure_parent_dir(priv_path)
    _ensure_parent_dir(pub_path)

    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not pub_path.exists():
            pub_pem = _serialize_public_key_pem(priv.public_key())
            _atomic_write_bytes(pub_path, pub_pem)
        return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = _serialize_private_key_pem(priv)
    pub_pem = _serialize_public_key_pem(priv.public_key())

    _atomic_write_bytes(priv_path, priv_pem)
    _atomic_write_bytes(pub_path, pub_pem)

def _ensure_aes_key(aes_path: Path, mode: str) -> None:
    """Ensures a 256-bit symmetric master key exists for AES-{mode}."""
    _ensure_parent_dir(aes_path)
    if aes_path.exists():
        return
    key_bytes = os.urandom(32)
    _atomic_write_bytes(aes_path, key_bytes)

def resolve_key_paths(env: Optional[Mapping[str, str]] = None) -> KeyPaths:
    getenv = (env or os.environ).get

    ec_priv = _get_env_path("RSA_ENC_PRIVATE_KEY_PATH", getenv("EC_ENC_PRIVATE_KEY_PATH", "./keys/rsa_enc_priv.pem"))
    ec_pub = _get_env_path("RSA_ENC_PUBLIC_KEY_PATH", getenv("EC_ENC_PUBLIC_KEY_PATH", "./keys/rsa_enc_pub.pem"))
    rsa_priv = _get_env_path("RSA_SIGN_PRIVATE_KEY_PATH", getenv("RSA_SIGN_PRIVATE_KEY_PATH", "./keys/rsa_sign_priv.pem"))
    rsa_pub = _get_env_path("RSA_SIGN_PUBLIC_KEY_PATH", getenv("RSA_SIGN_PUBLIC_KEY_PATH", "./keys/rsa_sign_pub.pem"))
    aes_mode = getenv("AES_MODE", "gcm") or "gcm"
    aes_key = _get_env_path("KMS_MASTER_KEY_PATH", getenv("KMS_MASTER_KEY_PATH", "./keys/kms_master.key"))

    return KeyPaths(
        ec_priv=ec_priv,
        ec_pub=ec_pub,
        rsa_priv=rsa_priv,
        rsa_pub=rsa_pub,
        aes_key=aes_key,
        aes_mode=aes_mode.lower(),
    )

def ensure_keys(env: Optional[Mapping[str, str]] = None) -> KeyPaths:
    """
    Ensure key material exists:
      - RSA (en rutas EC_ENC_*)  -> pensado para cifrado/encapsulación
      - RSA (en rutas RSA_SIGN_*) -> pensado para firmas
      - AES master key (raw 256-bit)
    Si existe la privada y falta la pública, se re-deriva.
    """
    paths = resolve_key_paths(env)

    # Ahora "EC" genera RSA 3072
    _ensure_ec_keypair(paths.ec_priv, paths.ec_pub)
    _ensure_rsa_keypair(paths.rsa_priv, paths.rsa_pub)
    _ensure_aes_key(paths.aes_key, paths.aes_mode)

    return paths

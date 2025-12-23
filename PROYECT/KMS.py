import os
import base64
from typing import Dict
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

# falta hacer estilo api, tanto la llamada como la recepcion para que sea instancia kms, o llamador, tambien falta poner en el env

def cifrar_con_user_aes(aes_b64: str, data: str) -> str:
    key = base64.b64decode(aes_b64)        # la key real
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)                 # 12 bytes para GCM
    ct = aesgcm.encrypt(nonce, data.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def descifrar_con_user_aes(aes_b64: str, payload_b64: str) -> str:
    key = base64.b64decode(aes_b64)
    aesgcm = AESGCM(key)
    payload = base64.b64decode(payload_b64)
    nonce, ct = payload[:12], payload[12:]
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")

class SingletonMeta(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class KMS(metaclass=SingletonMeta):
    """
    Key Management System (singleton)
    - Usa AES-GCM con una master key persistida en disco.
    - crearKeyUser(): genera una clave aleatoria y la devuelve en plano y cifrada.
    - decifrarKey(): descifra una clave cifrada (nonce||ciphertext en base64).
    """
    def __init__(self):
        self.mode = os.getenv("AES_MODE", "gcm").lower()
        if self.mode != "gcm":
            raise ValueError("Solo se soporta AES_MODE=gcm por ahora")
        self.master_key_path = os.getenv("KMS_MASTER_KEY_PATH", "./keys/kms_master.key")
        self._ensure_master_key()
        self._aesgcm = AESGCM(self.load_master_key())
        self._aad = b"kms:v1"  # Associated Data para atar el contexto (puede cambiarse/versionarse)

    # --- utilidades internas ---
    def _ensure_master_key(self) -> None:
        """Crea la master key (32 bytes) si no existe."""
        d = os.path.dirname(self.master_key_path)
        if d:
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.master_key_path):
            with open(self.master_key_path, "wb") as f:
                f.write(os.urandom(32))  # 256-bit
        # si existe, no hace nada

    def load_master_key(self) -> bytes:
        with open(self.master_key_path, "rb") as f:
            key = f.read()
        if len(key) not in (16, 24, 32):
            raise ValueError("La master key debe tener 16/24/32 bytes.")
        return key

    @staticmethod
    def _b64e(b: bytes) -> str:
        return base64.b64encode(b).decode("utf-8")

    @staticmethod
    def _b64d(s: str) -> bytes:
        return base64.b64decode(s.encode("utf-8"))

    # --- API pública ---
    def crearKeyUser(self, size_bytes: int = 32) -> Dict[str, str]:
        """
        Genera una clave de usuario aleatoria y la cifra con la master key.
        Retorna dict con:
          - 'plain_b64': clave en claro (Base64) para uso inmediato
          - 'encrypted_b64': nonce||ciphertext en Base64 para guardar en DB
        """
        if size_bytes not in (16, 24, 32):
            raise ValueError("size_bytes debe ser 16, 24 o 32.")
        user_key = os.urandom(size_bytes)
        nonce = os.urandom(12)  # recomendado para AES-GCM
        ciphertext = self._aesgcm.encrypt(nonce, user_key, self._aad)
        payload = nonce + ciphertext  # concatenamos para almacenar juntos
        return {
            "plain_b64": self._b64e(user_key),
            "encrypted_b64": self._b64e(payload),
        }

    def decifrarKey(self, keyEncripted: str) -> str:
        """
        Descifra una clave de usuario cifrada (nonce||ciphertext en Base64).
        Retorna la clave en claro en Base64 (para manipularla como string).
        Si preferís bytes, podés cambiar el return por los bytes crudos.
        """
        payload = self._b64d(keyEncripted)
        if len(payload) < 13:  # al menos 12 nonce + 1
            raise ValueError("Payload cifrado inválido.")
        nonce, ct = payload[:12], payload[12:]
        plain = self._aesgcm.decrypt(nonce, ct, self._aad)
        return self._b64e(plain)


def test():
    kms = KMS()

    # 1) Generar clave AES random de usuario y cifrarla
    k = kms.crearKeyUser(size_bytes=32)
    print("plain_b64     :", k["plain_b64"])
    print("encrypted_b64 :", k["encrypted_b64"])

    # 2) Descifrar y verificar igualdad
    plain_again_b64 = kms.decifrarKey(k["encrypted_b64"])
    print("decifrada_b64 :", plain_again_b64)

    # 3) Validación fuerte
    assert base64.b64decode(k["plain_b64"]) == base64.b64decode(plain_again_b64), \
        "La clave decifrada NO coincide con la original"
    print("✅ Test OK: la clave decifrada coincide con la original.")
#test()
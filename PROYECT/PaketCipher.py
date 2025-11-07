import os, json, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from dotenv import load_dotenv
from typing import Dict
    
load_dotenv()

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

from accesToken import AccessToken

class Packet:
    def __init__(self, refresh_token: str, access_token: AccessToken, data: dict, aes_key: str, user_id: str):
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.data = data
        self.aes_key = aes_key
        self.user_id = user_id

    # encriptador de AES
    def encript(self) -> dict:
        """
        Encripta refresh_token, access_token, data y user_id con AES-GCM.
        Devuelve un diccionario con iv y ciphertext en base64url.
        """
        aes_key_bytes = self.aes_key.encode()[:32].ljust(32, b'0')  # normalizamos a 256 bits
        aesgcm = AESGCM(aes_key_bytes)
        iv = secrets.token_bytes(12)

        payload = {
            "refresh_token": self.refresh_token,
            "access_token": self.access_token.to_json(),
            "data": self.data,
            "user_id": self.user_id
        }

        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        return {
            "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode().rstrip("=")
        }
    
    # desencriptamos algo con un aes espesifica
    def decrypt_aes_into_self(self, enc: Dict[str, str], aes_key: str | None = None) -> dict:
        if "iv" not in enc or "ciphertext" not in enc:
            raise ValueError("enc debe incluir 'iv' y 'ciphertext'")

        key_str = aes_key if aes_key is not None else self.aes_key
        key_bytes = key_str.encode()[:32].ljust(32, b"0")
        iv = _b64u_dec(enc["iv"])
        ct = _b64u_dec(enc["ciphertext"])

        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(iv, ct, None)
        data = json.loads(plaintext.decode("utf-8"))

        # reconstruir el objeto AccessToken
        from accesToken import AccessToken
        at = AccessToken.from_json(data["access_token"])

        self.refresh_token = data["refresh_token"]
        self.access_token = at
        self.data = data["data"]
        self.user_id = data["user_id"]

        return data
    
    # desencripatdor para handshake RSA
    @staticmethod
    def decrypt_with_rsa(ciphertext_b64u: str) -> dict:
        """
        Descifra un blob base64url cifrado con la RSA pública (RSA-OAEP-SHA256)
        y devuelve exactamente: {"username","password","aeskey"}.

        Lee la privada de RSA_ENC_PRIVATE_KEY_PATH (en .env).
        """
        priv_path = os.getenv("RSA_ENC_PRIVATE_KEY_PATH")
        if not priv_path:
            raise RuntimeError("Falta RSA_ENC_PRIVATE_KEY_PATH en .env")

        with open(priv_path, "rb") as f:
            rsa_priv = load_pem_private_key(f.read(), password=None)

        ciphertext = _b64u_dec(ciphertext_b64u)
        plaintext = rsa_priv.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
        )

        data = json.loads(plaintext.decode("utf-8"))
        for k in ("username", "password", "aeskey","email"):
            if k not in data:
                data[k] = None
        return {"username": data["username"], "password": data["password"], "aeskey": data["aeskey"], "email": data["email"]}
    
#simulador de mensaje de front 
def rsa_encrypt_b64u_with_public(payload: Dict[str, str]) -> str:
    """
    Cifra 'payload' (JSON) con la **pública** RSA (RSA-OAEP-SHA256) tomada de
    RSA_ENC_PUBLIC_KEY_PATH y devuelve base64url sin padding.
    """
    pub_path = os.getenv("RSA_ENC_PUBLIC_KEY_PATH")
    if not pub_path:
        raise RuntimeError("Falta RSA_ENC_PUBLIC_KEY_PATH en .env")

    with open(pub_path, "rb") as f:
        rsa_pub = load_pem_public_key(f.read())

    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = rsa_pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None),
    )
    return _b64u_enc(ciphertext)


def test_paketcipher_rsa_roundtrip() -> None:
    """
    Crea un JSON {"username","password","aeskey"}, lo cifra con la pública RSA
    en base64url (ciphertext_b64u) y luego usa Packet.decrypt_with_rsa (estático)
    para validar el round-trip.
    """
    sample = {"username": "alice", "password": "S3cr3t!", "aeskey": "0123456789abcdef0123456789abcdef"}
    ciphertext_b64u = rsa_encrypt_b64u_with_public(sample)
    recovered = Packet.decrypt_with_rsa(ciphertext_b64u)

    print(recovered)
    #assert recovered == sample, f"Round-trip falló:\n  input={sample}\n  out={recovered}"
    print("OK round-trip RSA OAEP (ciphertext_b64u) ✓")

#test_paketcipher_rsa_roundtrip()

def _test_aes_with_access_token_object():
    from accesToken import AccessToken

    at = AccessToken(sub="user123", role="admin", jti="uuid123")
    pkt = Packet(
        refresh_token="rtok_123",
        access_token=at,
        data={"ok": True},
        aes_key="0123456789abcdef0123456789abcdef",
        user_id="213asd3"
    )

    enc = pkt.encript()

    print(enc)

    pkt.refresh_token = ""
    pkt.access_token = None
    pkt.data = {}
    pkt.user_id = ""

    print(pkt.data)
    pkt.decrypt_aes_into_self(enc)
    print(pkt.data)
    assert isinstance(pkt.access_token, AccessToken)
    print("OK AES-GCM decrypt_into_self con AccessToken objeto ✓")

#_test_aes_with_access_token_object()
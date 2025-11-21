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
from FilesCipherHandler import FilesCipherHandler

class Packet:
    def __init__(self, refresh_token: str, access_token: AccessToken, data: dict, aes_key: str, user_id: str,files: list[dict] | None = None):
        #request format
        #cifradas
        self.refresh_token = refresh_token
        self.access_token = access_token
        self.data = data
        self.aes_key = aes_key
        self.iv = None
        #no cifrada 
        self.user_id = user_id # 0 significa que usa stateless, mas de 0 statefull. en realidad va a estar explicito en la func que usen en el modulo pero sirve para avisar
        self.files: list[dict] = files or []

    # encriptador de AES
    def encriptAES(self) -> dict:
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
        }

        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        out: dict = {
            "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode().rstrip("="),
            "user_id": self.user_id
        }

        if self.files:
            out["files"] = FilesCipherHandler.encrypt_files(self.files, self.aes_key)

        return out
    
    # desencriptamos algo con un aes espesifica
    @staticmethod
    def decryptAES(enc: Dict[str, str], aes_key: str | None = None) -> dict:
        if "iv" not in enc or "ciphertext" not in enc:
            raise ValueError("enc debe incluir 'iv' y 'ciphertext'")

        key_bytes = aes_key.encode()[:32].ljust(32, b"0")
        iv = _b64u_dec(enc["iv"])
        ct = _b64u_dec(enc["ciphertext"])

        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(iv, ct, None)
        data = json.loads(plaintext.decode("utf-8"))

         # --- archivos (si los hay) ---
        enc_files = enc.get("files") or []
        if enc_files:
            files = FilesCipherHandler.decrypt_files(enc_files, aes_key)
            data["files"] = files
        else:
            # por comodidad, siempre devolvemos "files"
            data.setdefault("files", [])

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
        return data
    
    
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
    sample = {"username": "alice", "password": "S3cr3t!", "aeskey": "0123456789abcdef0123456789abcdef","alfajor":"123"}
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

    enc = pkt.encriptAES()
    print(enc)

    data = Packet.decryptAES(enc, aes_key=pkt.aes_key)
    print(data)

    assert data["user_id"] == "213asd3"
    assert data["data"]["ok"] is True
    print("OK AES-GCM decrypt (estático) ✓")


#_test_aes_with_access_token_object()


def test_aes_packet_with_files() -> None:
    """
    Test de round-trip AES:
      - crea un Packet con data + 1 archivo
      - cifra con encriptAES()
      - descifra con decryptAES()
      - verifica que todo coincida
    """
    import uuid
    import base64

    # misma longitud que estás usando (32 chars -> 256 bits después del fill)
    aes_key = "0123456789abcdef0123456789abcdef"

    # AccessToken de prueba
    at = AccessToken(sub="user123", role="admin", jti=str(uuid.uuid4()))

    # archivo en PLANO (lo que usaría FilesCipherHandler.encrypt_files)
    original_bytes = b"hola mundo"
    files_plain = [
        {
            "id": "file_1",
            "file_name": "ejemplo.txt",
            "mime": "text/plain",
            "data_b64": base64.b64encode(original_bytes).decode("utf-8"),
        }
    ]

    # armamos el paquete
    pkt = Packet(
        refresh_token="rtok_123",
        access_token=at,
        data={"ok": True, "msg": "testing aes"},
        aes_key=aes_key,
        user_id="user-123",
        files=files_plain,
    )

    # ciframos
    enc = pkt.encriptAES()
    print("ENC (paquete cifrado):", enc)

    # desciframos con la función que unifica todo
    dec = Packet.decryptAES(enc, aes_key=aes_key)
    print("DEC (paquete decifrado):", dec)

    # --- asserts básicos ---
    assert dec["data"]["ok"] is True
    assert enc["user_id"] == "user-123"

    # verificamos que haya files y que el contenido coincida
    assert "files" in dec
    assert len(dec["files"]) == 1
    file_dec = dec["files"][0]
    recovered = base64.b64decode(file_dec["data_b64"].encode("utf-8"))
    assert recovered == original_bytes

    print("✅ Test AES Packet + Files OK")

#test_aes_packet_with_files()
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, secrets

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

class FilesCipherHandler:
    """
    Cifra/descifra un array de archivos usando la misma aes_key.
    Convención:
      - plano (antes de cifrar):
        {"id","file_name","mime","data_b64"}
      - cifrado (para transporte):
        {"id","file_name","mime","iv","ciphertext"}
    """

    @staticmethod
    def _key_bytes(aes_key: str) -> bytes:
        return aes_key.encode()[:32].ljust(32, b"0")  # 256 bits

    @staticmethod
    def encrypt_files(files: list[dict], aes_key: str) -> list[dict]:
        if not files:
            return []

        key = FilesCipherHandler._key_bytes(aes_key)
        aesgcm = AESGCM(key)
        out: list[dict] = []

        for f in files:
            data_b64 = f.get("data_b64")
            if data_b64 is None:
                continue  # o raise si querés ser más estricto

            raw = base64.b64decode(data_b64.encode("utf-8"))
            iv = secrets.token_bytes(12)
            ct = aesgcm.encrypt(iv, raw, None)

            out.append(
                {
                    "id": f.get("id"),
                    "file_name": f.get("file_name"),
                    "mime": f.get("mime"),
                    "iv": _b64u_enc(iv),
                    "ciphertext": _b64u_enc(ct),
                }
            )

        return out

    @staticmethod
    def decrypt_files(enc_files: list[dict], aes_key: str) -> list[dict]:
        if not enc_files:
            return []

        key = FilesCipherHandler._key_bytes(aes_key)
        aesgcm = AESGCM(key)
        out: list[dict] = []

        for f in enc_files:
            iv_s = f.get("iv")
            ct_s = f.get("ciphertext")
            if not iv_s or not ct_s:
                continue

            iv = _b64u_dec(iv_s)
            ct = _b64u_dec(ct_s)
            plain = aesgcm.decrypt(iv, ct, None)

            out.append(
                {
                    "id": f.get("id"),
                    "file_name": f.get("file_name"),
                    "mime": f.get("mime"),
                    "data_b64": base64.b64encode(plain).decode("utf-8"),
                }
            )

        return out

import os
import httpx
from dotenv import load_dotenv

from userModels import User
from KMS import KMS, cifrar_con_user_aes, descifrar_con_user_aes
from KMSCrypto import (
    env_bool,
    load_kms_pubkey,
    pack_hybrid,
    aesgcm_decrypt_json,
)

load_dotenv()

def _stripq(s: str) -> str:
    return (s or "").strip().strip('"').strip("'")

def _kms_base_url() -> str:
    base = _stripq(os.getenv("KMS_PATH", ""))
    if not base:
        raise RuntimeError("KMS_PATH vacio")
    return base.rstrip("/")

def _kms_timeout() -> float:
    try:
        return float(_stripq(os.getenv("KMS_TIMEOUT_SEC", "5")) or "5")
    except Exception:
        return 5.0

class KMSController:

    # -------------------------
    # Remote helpers (internos)
    # -------------------------
    @staticmethod
    def _remote_decifrar_key(aesEncriper_b64: str) -> str:
        """
        Pide al KMS instance que descifre la AES del usuario (user.aesEncriper).
        Devuelve aes_plain_b64.
        """
        kms_pub = load_kms_pubkey()  # en no-instancia solo existe pub
        env, sess_key = pack_hybrid(kms_pub, {"aesEncriper_b64": aesEncriper_b64})

        url = _kms_base_url() + "/v1/kms/decifrar-key"
        r = httpx.post(url, json=env, timeout=_kms_timeout())
        r.raise_for_status()

        resp = r.json()
        obj = aesgcm_decrypt_json(sess_key, resp["nonce_b64"], resp["ct_b64"])
        return obj["aes_plain_b64"]

    @staticmethod
    def _remote_crear_key_user() -> dict:
        """
        Pide al KMS instance que cree una AES de usuario nueva y devuelva:
          {"plain_b64": "...", "encrypted_b64": "..."}
        Si no queres que el plain viaje, lo sacamos.
        """
        kms_pub = load_kms_pubkey()
        env, sess_key = pack_hybrid(kms_pub, {"op": "crearKeyUser"})

        url = _kms_base_url() + "/v1/kms/crear-key-user"
        r = httpx.post(url, json=env, timeout=_kms_timeout())
        r.raise_for_status()

        resp = r.json()
        obj = aesgcm_decrypt_json(sess_key, resp["nonce_b64"], resp["ct_b64"])
        return obj

    # -------------------------
    # Public API del framework
    # -------------------------
    @staticmethod
    def getDataUncypher(user: User, data: str) -> str | None:
        """
        Desencripta un dato del usuario usando la AES privada del usuario.
        data: b64(ciphertext+iv) o lo que uses en tu cifrar_con_user_aes/descifrar_con_user_aes
        """
        if not data:
            return None

        try:
            if env_bool("KMS_IS_IT_INSTANCE", False):
                # Local: OK instanciar KMS
                kms = KMS()
                aes_plain_b64 = kms.decifrarKey(user.aesEncriper)
            else:
                # Remote: NO instanciar KMS
                aes_plain_b64 = KMSController._remote_decifrar_key(user.aesEncriper)

            return descifrar_con_user_aes(aes_plain_b64, data)

        except Exception as e:
            print("Error desencriptando dato:", e)
            return None

    @staticmethod
    def setDataCipher(user: User, data_claro: str):
        try:
            if env_bool("KMS_IS_IT_INSTANCE", False):
                kms = KMS()
                aes_plain_b64 = kms.decifrarKey(user.aesEncriper)
            else:
                aes_plain_b64 = KMSController._remote_decifrar_key(user.aesEncriper)

            return cifrar_con_user_aes(aes_plain_b64, data_claro)

        except Exception as e:
            print("Error encriptando dato:", e)
            return None

    @staticmethod
    def crearKeyUser():
        """
        Crea una AES para un usuario. Si somos KMS instance lo hace local.
        Si no, lo pide remoto.
        """
        if env_bool("KMS_IS_IT_INSTANCE", False):
            return KMS().crearKeyUser()
        return KMSController._remote_crear_key_user()

    @staticmethod
    def decifrarKey(aesEncriped):
        """
        Devuelve aes_plain_b64 a partir del aesEncriper (cifrado con master key).
        Misma idea: local si KMS instance, remoto si no.
        """
        if env_bool("KMS_IS_IT_INSTANCE", False):
            kms = KMS()
            return kms.decifrarKey(aesEncriped)
        return KMSController._remote_decifrar_key(aesEncriped)

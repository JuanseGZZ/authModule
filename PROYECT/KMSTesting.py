import os
import json
import tempfile
import unittest
from dataclasses import dataclass
from typing import Any, Dict
from unittest.mock import patch

# Intento importar tu User real; si no existe, creo uno dummy para tests
try:
    from userModels import User  # type: ignore
except Exception:
    @dataclass
    class User:  # fallback
        aesEncriper: str

from fastapi import FastAPI
from fastapi.testclient import TestClient

from KMS import KMS, cifrar_con_user_aes, descifrar_con_user_aes
from KMSCrypto import (
    ensure_kms_rsa_keys_once,
    load_kms_pubkey,
    load_kms_privkey,
    pack_hybrid,
    unpack_hybrid,
    aesgcm_decrypt_json,
    env_bool,
)

import KMSApi
from KMSController import KMSController


class _FakeHTTPResponse:
    def __init__(self, status_code: int, json_obj: Dict[str, Any]):
        self.status_code = status_code
        self._json_obj = json_obj

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}: {self._json_obj}")

    def json(self):
        return self._json_obj


class KMSTesting(unittest.TestCase):
    def setUp(self):
        # Aislar filesystem por test run
        self.tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmp.name

        # Paths
        self.keys_dir = os.path.join(self.tmpdir, "keys")
        os.makedirs(self.keys_dir, exist_ok=True)

        self.master_key_path = os.path.join(self.keys_dir, "kms_master.key")
        self.rsa_pub_path = os.path.join(self.keys_dir, "kms_pub.pem")
        self.rsa_pri_path = os.path.join(self.keys_dir, "kms_priv.pem")

        # Env base
        os.environ["AES_MODE"] = "gcm"
        os.environ["KMS_MASTER_KEY_PATH"] = self.master_key_path
        os.environ["KMS_KEY_PATH_PUB"] = self.rsa_pub_path
        os.environ["KMS_KEY_PATH_PRI"] = self.rsa_pri_path
        os.environ["KMS_TIMEOUT_SEC"] = "5"

        # Para tests que mockean remoto
        os.environ["KMS_PATH"] = "http://kms.local"

    def tearDown(self):
        self.tmp.cleanup()

    # -------------------------
    # Helpers
    # -------------------------
    def _make_app_and_client(self) -> TestClient:
        app = FastAPI()
        app.include_router(KMSApi.router)
        return TestClient(app)

    # -------------------------
    # Tests KMS.py
    # -------------------------
    def test_kms_crear_y_decifrar_user_key_roundtrip(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        kms = KMS()
        created = kms.crearKeyUser(size_bytes=32)
        plain_b64 = created["plain_b64"]
        encrypted_b64 = created["encrypted_b64"]

        plain_again_b64 = kms.decifrarKey(encrypted_b64)
        self.assertEqual(plain_b64, plain_again_b64)

    def test_user_data_encrypt_decrypt_helpers(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        kms = KMS()
        created = kms.crearKeyUser(size_bytes=32)
        aes_plain_b64 = created["plain_b64"]

        msg = "hola mundo"
        cipher_b64 = cifrar_con_user_aes(aes_plain_b64, msg)
        msg2 = descifrar_con_user_aes(aes_plain_b64, cipher_b64)
        self.assertEqual(msg, msg2)

    # -------------------------
    # Tests KMSCrypto.py
    # -------------------------
    def test_rsa_keys_once_and_hybrid_pack_unpack(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        ensure_kms_rsa_keys_once()
        pub = load_kms_pubkey()
        priv = load_kms_privkey()

        payload = {"x": 1, "msg": "test"}
        env, sess_key = pack_hybrid(pub, payload)
        obj, sess_key2 = unpack_hybrid(priv, env)

        self.assertEqual(obj, payload)
        self.assertEqual(sess_key, sess_key2)

    # -------------------------
    # Tests KMSApi endpoints
    # -------------------------
    def test_api_decifrar_key_endpoint(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        # preparar keys RSA y user key
        ensure_kms_rsa_keys_once()
        kms = KMS()
        created = kms.crearKeyUser(size_bytes=32)
        aes_plain_b64 = created["plain_b64"]
        aes_enc_b64 = created["encrypted_b64"]

        # construir request cifrado con pub RSA
        pub = load_kms_pubkey()
        env, sess_key = pack_hybrid(pub, {"aesEncriper_b64": aes_enc_b64})

        client = self._make_app_and_client()
        r = client.post("/v1/kms/decifrar-key", json=env)
        self.assertEqual(r.status_code, 200)

        resp = r.json()
        obj = aesgcm_decrypt_json(sess_key, resp["nonce_b64"], resp["ct_b64"])
        self.assertEqual(obj["aes_plain_b64"], aes_plain_b64)

    def test_api_crear_key_user_endpoint(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        ensure_kms_rsa_keys_once()
        pub = load_kms_pubkey()
        env, sess_key = pack_hybrid(pub, {"op": "crearKeyUser"})

        client = self._make_app_and_client()
        r = client.post("/v1/kms/crear-key-user", json=env)
        self.assertEqual(r.status_code, 200)

        resp = r.json()
        obj = aesgcm_decrypt_json(sess_key, resp["nonce_b64"], resp["ct_b64"])

        self.assertIn("plain_b64", obj)
        self.assertIn("encrypted_b64", obj)

        # Validar coherencia usando KMS local
        kms = KMS()
        plain_again = kms.decifrarKey(obj["encrypted_b64"])
        self.assertEqual(plain_again, obj["plain_b64"])

    # -------------------------
    # Tests KMSController local
    # -------------------------
    def test_controller_local_encrypt_decrypt_roundtrip(self):
        os.environ["KMS_IS_IT_INSTANCE"] = "true"

        kms = KMS()
        created = kms.crearKeyUser(size_bytes=32)

        user = User(aesEncriper=created["encrypted_b64"])

        msg = "secreto"
        cipher = KMSController.setDataCipher(user, msg)
        plain = KMSController.getDataUncypher(user, cipher)

        self.assertEqual(msg, plain)

    # -------------------------
    # Tests KMSController remoto (sin servidor real)
    # -------------------------
    def test_controller_remote_encrypt_decrypt_roundtrip(self):
        # Armamos un TestClient que simula el KMS instance
        os.environ["KMS_IS_IT_INSTANCE"] = "true"
        ensure_kms_rsa_keys_once()
        client = self._make_app_and_client()

        # Creamos user key en el KMS instance real (local del test)
        kms = KMS()
        created = kms.crearKeyUser(size_bytes=32)
        user = User(aesEncriper=created["encrypted_b64"])

        # Ahora pasamos a modo NO instancia para el controller
        os.environ["KMS_IS_IT_INSTANCE"] = "false"

        # El remoto necesita la pub key local en archivo. Ya existe por ensure_kms_rsa_keys_once()
        # Mockeamos la llamada HTTP (httpx o requests) para que pegue al TestClient.

        def _dispatch_post(url: str, json: Dict[str, Any], timeout: Any = None):
            # extrae el path de la URL
            # ejemplo: http://kms.local/v1/kms/decifrar-key
            path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
            r = client.post(path, json=json)
            return _FakeHTTPResponse(r.status_code, r.json())

        # Detecta si tu controller usa httpx o requests
        # Tu KMSController actual importaba httpx; si lo cambiaste a requests, esto igual funciona.
        target = None
        try:
            import httpx  # noqa
            target = "KMSController.httpx.post"
        except Exception:
            target = "KMSController.requests.post"

        with patch(target, side_effect=_dispatch_post):
            msg = "remote secreto"
            cipher = KMSController.setDataCipher(user, msg)
            plain = KMSController.getDataUncypher(user, cipher)
            self.assertEqual(msg, plain)

    def test_controller_remote_crear_key_user(self):
        # KMS instance app
        os.environ["KMS_IS_IT_INSTANCE"] = "true"
        ensure_kms_rsa_keys_once()
        client = self._make_app_and_client()

        # Controller remoto
        os.environ["KMS_IS_IT_INSTANCE"] = "false"

        def _dispatch_post(url: str, json: Dict[str, Any], timeout: Any = None):
            path = "/" + url.split("://", 1)[-1].split("/", 1)[-1]
            r = client.post(path, json=json)
            return _FakeHTTPResponse(r.status_code, r.json())

        target = None
        try:
            import httpx  # noqa
            target = "KMSController.httpx.post"
        except Exception:
            target = "KMSController.requests.post"

        with patch(target, side_effect=_dispatch_post):
            created = KMSController.crearKeyUser()
            self.assertIn("plain_b64", created)
            self.assertIn("encrypted_b64", created)


if __name__ == "__main__":
    unittest.main()

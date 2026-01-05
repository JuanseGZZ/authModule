from KMSCrypto import (
    load_kms_pubkey,
    pack_hybrid,
    aesgcm_decrypt_json,
)
import httpx
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://localhost:8081"

# -------------------------------------------------
# 1) CREAR KEY USER (remoto)
# -------------------------------------------------
pub = load_kms_pubkey()

env_create, sess_create = pack_hybrid(pub, {"op": "crearKeyUser"})
r = httpx.post(f"{BASE_URL}/v1/kms/crear-key-user", json=env_create, timeout=5)
r.raise_for_status()

resp_create = r.json()
obj_create = aesgcm_decrypt_json(
    sess_create,
    resp_create["nonce_b64"],
    resp_create["ct_b64"],
)

plain_b64 = obj_create["plain_b64"]
encrypted_b64 = obj_create["encrypted_b64"]

print("CREATED")
print("plain_b64     :", plain_b64)
print("encrypted_b64 :", encrypted_b64)

# -------------------------------------------------
# 2) DECIFRAR KEY (remoto)
# -------------------------------------------------
env_dec, sess_dec = pack_hybrid(
    pub,
    {"aesEncriper_b64": encrypted_b64}
)

r = httpx.post(f"{BASE_URL}/v1/kms/decifrar-key", json=env_dec, timeout=5)
r.raise_for_status()

resp_dec = r.json()
obj_dec = aesgcm_decrypt_json(
    sess_dec,
    resp_dec["nonce_b64"],
    resp_dec["ct_b64"],
)

plain_again_b64 = obj_dec["aes_plain_b64"]

print("DECRYPTED")
print("aes_plain_b64 :", plain_again_b64)

# -------------------------------------------------
# 3) VALIDACION FUERTE
# -------------------------------------------------
assert plain_b64 == plain_again_b64, "ERROR: la clave decifrada no coincide"

print("OK: crear-key-user y decifrar-key funcionan correctamente")

from KMSCrypto import load_kms_pubkey, pack_hybrid, aesgcm_decrypt_json
import httpx, os
from dotenv import load_dotenv
load_dotenv()

pub = load_kms_pubkey()

env, sess = pack_hybrid(pub, {"op":"crearKeyUser"})
r = httpx.post("http://localhost:8081/v1/kms/crear-key-user", json=env, timeout=5)
r.raise_for_status()
resp = r.json()

obj = aesgcm_decrypt_json(sess, resp["nonce_b64"], resp["ct_b64"])
print(obj)  # deberia traer plain_b64 y encrypted_b64

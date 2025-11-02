
from typing import Dict, Any
import base64, json
from fastapi import Depends, HTTPException, Request
from starlette.status import HTTP_400_BAD_REQUEST
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64url_decode(s: str) -> bytes:
  s = s.replace("-", "+").replace("_", "/")
  pad = "=" * ((4 - len(s) % 4) % 4)
  return base64.b64decode(s + pad)

# Reemplazar por integración con KMS/archivo según 'kid'
def load_private_key_for_kid(kid: str) -> rsa.RSAPrivateKey:
  path = f"./keys-front-enc/private_{kid}.pem"
  with open(path, "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
  assert isinstance(key, rsa.RSAPrivateKey)
  return key

def decrypt_front_payload(front_enc: Dict[str, Any]) -> Dict[str, Any]:
  kid = front_enc.get("kid"); alg = front_enc.get("alg"); enc = front_enc.get("enc")
  cek_wrapped = front_enc.get("cek"); iv_b64 = front_enc.get("iv"); ct_b64 = front_enc.get("ct")
  if not (kid and alg and enc and cek_wrapped and iv_b64 and ct_b64):
    raise ValueError("__front_enc__ incompleto")
  if alg != "RSA-OAEP-256" or enc != "A256GCM":
    raise ValueError("Algoritmos no soportados")
  private_key = load_private_key_for_kid(kid)
  cek_raw = private_key.decrypt(
    b64url_decode(cek_wrapped),
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
  )
  iv = b64url_decode(iv_b64); ct = b64url_decode(ct_b64)
  aesgcm = AESGCM(cek_raw)
  try:
    plaintext = aesgcm.decrypt(iv, ct, None)
  except Exception as e:
    raise ValueError(f"Decryption failed: {e}")
  try:
    obj = json.loads(plaintext.decode("utf-8"))
  except Exception:
    raise ValueError("JSON inválido tras descifrar")
  return obj

async def require_and_decrypt_dependency(req: Request) -> Dict[str, Any]:
  payload = await req.json()
  if "__front_enc__" not in payload:
    return payload
  try:
    return decrypt_front_payload(payload["__front_enc__"])
  except ValueError as e:
    raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail={"error": {"code": "AUTH_BAD_REQUEST", "message": str(e)}})

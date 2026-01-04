from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from KMS import KMS
from KMSCrypto import load_kms_privkey, unpack_hybrid, aesgcm_encrypt_json, ensure_kms_keys_present

load_dotenv()
router = APIRouter(prefix="/v1/kms", tags=["kms"])

class HybridReq(BaseModel):
    ek_b64: str
    nonce_b64: str
    ct_b64: str

class HybridResp(BaseModel):
    nonce_b64: str
    ct_b64: str

@router.post("/decifrar-key", response_model=HybridResp)
def api_decifrar_key(req: HybridReq):
    try:
        ensure_kms_keys_present()
        priv = load_kms_privkey()

        obj, sess_key = unpack_hybrid(priv, req.model_dump())
        aes_enc_b64 = obj.get("aesEncriper_b64")
        if not aes_enc_b64:
            raise HTTPException(status_code=400, detail="aesEncriper_b64 missing")

        aes_plain_b64 = KMS().decifrarKey(aes_enc_b64)
        enc = aesgcm_encrypt_json(sess_key, {"aes_plain_b64": aes_plain_b64})
        return HybridResp(**enc)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/crear-key-user", response_model=HybridResp)
def api_crear_key_user(req: HybridReq):
    try:
        ensure_kms_keys_present()
        priv = load_kms_privkey()

        obj, sess_key = unpack_hybrid(priv, req.model_dump())
        # obj puede traer {"op":"crearKeyUser"} por consistencia; no es obligatorio
        created = KMS().crearKeyUser()  # tu funcion devuelve dict con plain_b64/encrypted_b64 :contentReference[oaicite:0]{index=0}

        enc = aesgcm_encrypt_json(sess_key, created)
        return HybridResp(**enc)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

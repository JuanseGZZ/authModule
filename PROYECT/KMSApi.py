from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from KMS import KMS
from KMSCrypto import ensure_kms_rsa_keys_once, load_kms_privkey, unpack_hybrid, aesgcm_encrypt_json

load_dotenv()
router = APIRouter(prefix="/v1/kms", tags=["kms"])

class HybridReq(BaseModel):
    ek_b64: str
    nonce_b64: str
    ct_b64: str

class HybridResp(BaseModel):
    nonce_b64: str
    ct_b64: str

@router.post("/decrypt-user-aes", response_model=HybridResp)
def decrypt_user_aes(req: HybridReq):
    try:
        ensure_kms_rsa_keys_once()
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

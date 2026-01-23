# authApi.py
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import auth  # tu framework (auth.py)

# ============================================================
# Inicializacion segura (para que no se ejecute init mil veces)
# ============================================================
_AUTH_INIT_DONE = False


def init_auth_api() -> None:
    """
    Inicializa el framework de auth (DB, keys, etc.) una sola vez.
    Recomendado llamarlo en el startup del servicio que consuma este router.
    """
    global _AUTH_INIT_DONE
    if _AUTH_INIT_DONE:
        return
    auth.init()
    _AUTH_INIT_DONE = True


# ============================================================
# Modelos de request (minimos)
# ============================================================
class HandshakeRequest(BaseModel):
    # En tu auth.py aceptas handshake_b64u o ciphertext_b64u como alias. :contentReference[oaicite:2]{index=2}
    handshake_b64u: Optional[str] = Field(default=None)
    ciphertext_b64u: Optional[str] = Field(default=None)


class StatefulOrStatelessPacketRequest(BaseModel):
    # refresh/unlogin usan user_id para branch stateful vs stateless. :contentReference[oaicite:3]{index=3}
    user_id: str

    # Paquete AES (si aplica)
    iv: Optional[str] = None
    ciphertext: Optional[str] = None

    # En stateless, auth.refresh y auth.unlogin esperan aes.ciphertext RSA. :contentReference[oaicite:4]{index=4}
    aes: Optional[Dict[str, Any]] = None

    # opcional (tu Packet soporta files en otras funcs)
    files: Optional[Any] = None


# ============================================================
# Router exportable
# ============================================================
router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _bad_request(detail: str) -> None:
    raise HTTPException(status_code=400, detail=detail)


@router.post("/register")
def api_register(req: HandshakeRequest) -> Dict[str, Any]:
    # auth.register exige handshake_b64u o ciphertext_b64u. :contentReference[oaicite:5]{index=5}
    if not (req.handshake_b64u or req.ciphertext_b64u):
        _bad_request("Falta 'handshake_b64u' o 'ciphertext_b64u' en el request")

    try:
        return auth.register(req.model_dump(exclude_none=True))
    except ValueError as e:
        _bad_request(str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno register: {str(e)}")


@router.post("/login")
def api_login(req: HandshakeRequest) -> Dict[str, Any]:
    # auth.login exige handshake_b64u o ciphertext_b64u. :contentReference[oaicite:6]{index=6}
    if not (req.handshake_b64u or req.ciphertext_b64u):
        _bad_request("Falta 'handshake_b64u' o 'ciphertext_b64u' en el request")

    try:
        return auth.login(req.model_dump(exclude_none=True))
    except ValueError as e:
        _bad_request(str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno login: {str(e)}")


@router.post("/refresh")
def api_refresh(req: StatefulOrStatelessPacketRequest) -> Dict[str, Any]:
    # auth.refresh requiere user_id. :contentReference[oaicite:7]{index=7}
    if not req.user_id:
        _bad_request("Falta 'user_id'")

    body = req.model_dump(exclude_none=True)

    # Validacion minima por modo:
    if req.user_id == "0":
        # stateless requiere aes.ciphertext RSA. :contentReference[oaicite:8]{index=8}
        aes = body.get("aes")
        if not isinstance(aes, dict) or "ciphertext" not in aes:
            _bad_request("Stateless: falta 'aes.ciphertext' (RSA)")

        if not body.get("iv") or not body.get("ciphertext"):
            _bad_request("Stateless: faltan 'iv' y/o 'ciphertext' del paquete AES")
    else:
        # stateful requiere paquete AES normal (iv/ciphertext). :contentReference[oaicite:9]{index=9}
        if not body.get("iv") or not body.get("ciphertext"):
            _bad_request("Stateful: faltan 'iv' y/o 'ciphertext' del paquete AES")

    try:
        return auth.refresh(body)
    except ValueError as e:
        _bad_request(str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno refresh: {str(e)}")


@router.post("/unlogin")
def api_unlogin(req: StatefulOrStatelessPacketRequest) -> Dict[str, Any]:
    # auth.unlogin requiere user_id. :contentReference[oaicite:10]{index=10}
    if not req.user_id:
        _bad_request("Falta 'user_id'")

    body = req.model_dump(exclude_none=True)

    # Validacion minima por modo:
    if req.user_id == "0":
        aes = body.get("aes")
        if not isinstance(aes, dict) or "ciphertext" not in aes:
            _bad_request("Stateless: falta 'aes.ciphertext' (RSA)")

        if not body.get("iv") or not body.get("ciphertext"):
            _bad_request("Stateless: faltan 'iv' y/o 'ciphertext' del paquete AES")
    else:
        if not body.get("iv") or not body.get("ciphertext"):
            _bad_request("Stateful: faltan 'iv' y/o 'ciphertext' del paquete AES")

    try:
        return auth.unlogin(body)
    except ValueError as e:
        _bad_request(str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno unlogin: {str(e)}")


# para la public
from fastapi import Response
import os
from ensureKeys import ensure_keys

@router.get("/public-key")
def api_public_key(response: Response) -> Dict[str, Any]:
    # Asegura que existan las keys y obtiene path de la public
    keys = ensure_keys()
    pub_path = keys.ec_pub  # RSA de cifrado (en tu ensure_keys "ec" genera RSA 3072)

    pem = pub_path.read_text(encoding="utf-8")

    # Cache HTTP (opcional pero bueno): 1 año, immutable
    # Si algun dia rotas la key, cambia el valor kid y el front la vuelve a pedir.
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"

    # "kid" simple basado en mtime y size (suficiente para invalidar cache)
    st = os.stat(pub_path)
    kid = f"rsa-enc-{int(st.st_mtime)}-{st.st_size}"

    return {"public_key_pem": pem, "kid": kid}

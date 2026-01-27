from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Body
from authApi import router as auth_router, init_auth_api
import auth

from contextlib import asynccontextmanager
from fastapi import FastAPI
from authApi import router as auth_router, init_auth_api

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_auth_api()
    yield
    # shutdown (si algun dia queres)

app = FastAPI(lifespan=lifespan)

app.include_router(auth_router)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8081",
        "http://localhost:8081",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




# ============================================================
# CUSTOM TEST endpoints: uncyph al inicio, cyph al final
# ============================================================

@app.post("/v1/auth/_test/pipeline/stateless")
def test_pipeline_stateless(packet: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """
    Espera un paquete cifrado stateless (user_id="0"):
      - packet["aes"]["ciphertext"] : AES key cifrada con RSA
      - packet["iv"], packet["ciphertext"] : paquete AES

    Pipeline:
      1) dec = auth.uncyphStateLess(packet)
      2) logica en claro (modificar/armar respuesta)
      3) resp_packet = auth.cyphStateLess(resp_dec_con___aes_key)
      4) devuelve paquete cifrado
    """
    try:
        # 1) UNCypher al inicio
        dec = auth.uncyphStateLess(packet)

        # 2) Logica en claro (ejemplo: echo + marca server)
        # dec trae __aes_key segun tu helper, lo preservamos para volver a cifrar.
        aes_key = dec.get("__aes_key")
        if not isinstance(aes_key, str) or not aes_key:
            raise HTTPException(status_code=500, detail="No vino '__aes_key' del uncyph stateless")

        # Armo payload de respuesta en claro (puede ser otro distinto al dec original)
        resp_dec: Dict[str, Any] = {
            # requerido por cyphStateLess: user_id y __aes_key
            "user_id": "0",
            "__aes_key": aes_key,

            # contenido en claro que quieras retornar
            "ok": True,
            "type": "stateless_pipeline",
            "data": dec,              # devolvemos lo que llego en claro
            "server_note": "roundtrip_ok",
        }


        # 3) Cypher al final
        resp_packet = auth.cyphStateLess(resp_dec)

        # 4) Respuesta cifrada
        return resp_packet

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno pipeline stateless: {str(e)}")


@app.post("/v1/auth/_test/pipeline/stateful")
def test_pipeline_stateful(packet: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """
    Espera un paquete cifrado stateful (user_id != "0"):
      - packet["user_id"]
      - packet["iv"], packet["ciphertext"]

    Pipeline:
      1) dec = auth.uncyphStateFull(packet)
      2) logica en claro
      3) resp_packet = auth.cyphStateFull(resp_dec_con_user_id)
      4) devuelve paquete cifrado
    """
    try:
        # 1) UNCypher al inicio
        dec = auth.uncyphStateFull(packet)

        user_id = dec.get("__user_id") or dec.get("user_id") or packet.get("user_id")
        if not isinstance(user_id, str) or not user_id or user_id == "0":
            raise HTTPException(status_code=400, detail="Stateful: falta 'user_id' valido (distinto de '0')")

        # 2) Logica en claro (ejemplo: echo + marca server)
        resp_dec: Dict[str, Any] = {
            # requerido por cyphStateFull: user_id
            "user_id": user_id,

            "ok": True,
            "type": "stateful_pipeline",
            "echo": dec,
            "server_note": "roundtrip_ok",
        }

        # 3) Cypher al final (toma AES del SF por user_id)
        resp_packet = auth.cyphStateFull(resp_dec)

        # 4) Respuesta cifrada
        return resp_packet

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno pipeline stateful: {str(e)}")

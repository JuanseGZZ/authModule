# KMSServer.py
import os
from dotenv import load_dotenv
from fastapi import FastAPI
import uvicorn

from KMSApi import router as kms_router
from KMSCrypto import ensure_kms_keys_present
from KMS import KMS

load_dotenv()

def create_app() -> FastAPI:
    app = FastAPI(title="KMS Server", version="v1")
    app.include_router(kms_router)

    @app.on_event("startup")
    def _startup():
        # 1) genera kms_pub.pem / kms_priv.pem si faltan
        ensure_kms_keys_present()
        # 2) asegura master key para AES-user (si tu KMS la crea on-demand)
        KMS()

    return app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("KMS_HOST", "0.0.0.0")
    port = int(os.getenv("KMS_PORT", "8081"))
    uvicorn.run("KMSServer:app", host=host, port=port, reload=True)

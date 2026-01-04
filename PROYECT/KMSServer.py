# KMSServer.py
import os
from dotenv import load_dotenv
from fastapi import FastAPI
import uvicorn

# Router de tu API KMS
from KMSApi import router as kms_router

load_dotenv()

def create_app() -> FastAPI:
    app = FastAPI(title="KMS Server", version="v1")
    app.include_router(kms_router)  # expone /v1/kms/...
    return app

app = create_app()

if __name__ == "__main__":
    # Por defecto usa 8081 para no pisar tu app principal (APP_PORT=8080 en tu .env)
    host = os.getenv("KMS_HOST", "0.0.0.0")
    port = int(os.getenv("KMS_PORT", "8081"))
    uvicorn.run("KMSServer:app", host=host, port=port, reload=True)

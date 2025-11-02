from fastapi import FastAPI
from app.core.config import settings
from app.api import auth as auth_api

app = FastAPI(title="Auth MVP", version="0.1.0")

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

app.include_router(auth_api.router, prefix="/auth", tags=["auth"])

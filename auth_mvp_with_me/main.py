
from fastapi import FastAPI
from api.auth import router as auth_router
from api.jwks import router as jwks_router

app = FastAPI(title="auth-mvp")

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(jwks_router, tags=["jwks"])

# NOTE: run with: uvicorn main:app --reload

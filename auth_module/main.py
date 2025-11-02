
import os
from fastapi import FastAPI
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from utils.security_headers import SecurityHeadersMiddleware
from utils.audit import AuditMiddleware
from api import auth, jwks, health

def create_app() -> FastAPI:
    load_dotenv()
    app = FastAPI(title="Auth Module", version="0.1.0")

    # CORS
    allow_origins = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")]
    allow_methods = [m.strip() for m in os.getenv("CORS_ALLOW_METHODS", "GET,POST,OPTIONS").split(",")]
    allow_headers = [h.strip() for h in os.getenv("CORS_ALLOW_HEADERS", "*").split(",")]
    allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true"
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
    )

    # Security headers & Audit
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditMiddleware)

    # Routers
    app.include_router(health.router)
    app.include_router(jwks.router, prefix="")
    app.include_router(auth.router, prefix="/auth")

    return app

app = create_app()

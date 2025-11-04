from fastapi import FastAPI
from api.auth_api import router as auth_router
from api.health_api import router as health_router

def create_app() -> FastAPI:
    app = FastAPI(title="Auth Module", version="1.0.0")
    app.include_router(health_router)
    app.include_router(auth_router)
    return app

app = create_app()

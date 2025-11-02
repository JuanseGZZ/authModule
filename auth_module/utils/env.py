
import os
from pydantic import BaseModel

class Settings(BaseModel):
    app_env: str = os.getenv("APP_ENV", "dev")
    iss: str = os.getenv("APP_ISS", "http://localhost:8000")
    aud: str = os.getenv("APP_AUD", "web")
    access_ttl: int = int(os.getenv("ACCESS_TTL_SECONDS", "900"))
    refresh_ttl: int = int(os.getenv("REFRESH_TTL_SECONDS", "1209600"))
    clock_skew: int = int(os.getenv("CLOCK_SKEW_SECONDS", "60"))
    keys_dir: str = os.getenv("KEYS_DIR", "env/keys")
    jwks_sig_kid: str = os.getenv("JWKS_KEY_SIG_ACTIVE_KID", "sig-dev-1")
    jwks_enc_kid: str = os.getenv("JWKS_KEY_ENC_ACTIVE_KID", "enc-dev-1")
    jwks_front_kid: str = os.getenv("JWKS_KEY_FRONT_ACTIVE_KID", "enc-front-dev-1")
    key_rotation_grace: int = int(os.getenv("KEY_ROTATION_GRACE_SECONDS", "86400"))
    refresh_cookie_name: str = os.getenv("REFRESH_COOKIE_NAME", "__Host-refresh")
    refresh_cookie_secure: bool = os.getenv("REFRESH_COOKIE_SECURE", "false").lower() == "true"
    refresh_cookie_samesite: str = os.getenv("REFRESH_COOKIE_SAMESITE", "Lax")
    refresh_cookie_path: str = os.getenv("REFRESH_COOKIE_PATH", "/auth")
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://auth_user:auth_pass@localhost:5432/auth_db")

settings = Settings()

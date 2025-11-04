import os

class Config:
    APP_NAME = os.environ.get("APP_NAME", "auth-module")
    ENV = os.environ.get("ENV", "dev")

    DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "authdb")
    DB_USER = os.environ.get("DB_USER", "authuser")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "authpass")
    DB_MIN_CONN = int(os.environ.get("DB_MIN_CONN", "1"))
    DB_MAX_CONN = int(os.environ.get("DB_MAX_CONN", "10"))
    DB_CONNECT_TIMEOUT = int(os.environ.get("DB_CONNECT_TIMEOUT", "5"))

    JWT_ALG = os.environ.get("JWT_ALG", "RS256")
    JWT_PRIVATE_KEY_PATH = os.environ.get("JWT_PRIVATE_KEY_PATH", "./keys/private.pem")
    JWT_PUBLIC_KEY_PATH = os.environ.get("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")
    JWT_SECRET = os.environ.get("JWT_SECRET", "")
    ACCESS_EXP_MIN = int(os.environ.get("ACCESS_EXP_MIN", "15"))
    REFRESH_EXP_DAYS = int(os.environ.get("REFRESH_EXP_DAYS", "7"))
    ISS = os.environ.get("JWT_ISS", "auth.svc")
    AUD = os.environ.get("JWT_AUD", "all")

CFG = Config()

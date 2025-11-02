from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    AUTH_JWT_SECRET: str
    AUTH_ACCESS_TTL_MIN: int = 15
    AUTH_REFRESH_TTL_DAYS: int = 14
    AUTH_BCRYPT_ROUNDS: int = 12
    AUTH_ISS: str = "https://tu-api"
    AUTH_AUD: str = "tu-spa"
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/authdb"
    RATE_LIMIT_LOGIN_PER_IP_PER_15M: int = 50
    RATE_LIMIT_REFRESH_PER_IP_PER_15M: int = 200

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

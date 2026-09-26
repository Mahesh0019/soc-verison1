from functools import lru_cache
from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Mini SIEM Dashboard"
    api_prefix: str = "/api"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://siem:siem@localhost:5432/mini_siem"
    jwt_secret_key: str = Field(default="change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 12
    cors_origins: list[AnyHttpUrl | str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    max_upload_bytes: int = 2 * 1024 * 1024
    allowed_upload_extensions: set[str] = {".json", ".csv", ".txt", ".log"}
    auto_create_tables: bool = True
    # Juice Shop connector - disabled by default so local dev is unaffected
    enable_juice_shop_connector: bool = False
    juice_shop_telemetry_url: str = "https://demo-victim-1.onrender.com/api/telemetry/events"
    juice_shop_telemetry_api_key: str = ""
    poll_interval_seconds: float = 10.0
    batch_size: int = 50


    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

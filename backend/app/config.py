from __future__ import annotations
import json
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    allowed_origins: str = Field(
        default='["http://localhost:5173","http://localhost:3000"]',
        alias="ALLOWED_ORIGINS",
    )
    data_dir: str = "./data"
    session_ttl_hours: int = 24
    rate_limit: str = "60/minute"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
    )

    def get_allowed_origins(self) -> list[str]:
        v = self.allowed_origins.strip()
        if v == "*":
            return ["*"]
        if v.startswith("["):
            return json.loads(v)
        return [o.strip() for o in v.split(",") if o.strip()]


settings = Settings()

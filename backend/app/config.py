from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    allowed_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    data_dir: str = "./data"
    session_ttl_hours: int = 24
    rate_limit: str = "60/minute"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()

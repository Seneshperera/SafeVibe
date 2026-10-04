from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    cors_origins: str = "http://localhost:5173"
    max_text_chars: int = 5000
    max_urls: int = 10
    max_url_chars: int = 2048
    max_conversation_messages: int = 50
    max_message_chars: int = 2000
    rules_version: str = "rules_v1"
    weights_version: str = "weights_v1"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

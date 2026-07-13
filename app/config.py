# app/config.py
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "PromptShield Deep Scan Engine"
    VERSION: str = "1.0.0"

    # Allow local React dashboard and Chrome Extensions
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",  # Vite default
        "http://localhost:3000",
        "*"  # Allow all for local extension testing
    ]

    DEFAULT_SPACY_MODEL: str = "en_core_web_lg"
    DEFAULT_CONFIDENCE_THRESHOLD: float = 0.60


settings = Settings()
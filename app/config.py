"""
Doc cau hinh tu file .env.
Khong dung pydantic-settings de giu don gian, de hieu cho sinh vien.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # doc file .env o thu muc goc du an


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./scamsieve.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-this-secret-key-in-production")
    ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "psieve-admin-secret-key-2024")
    SESSION_COOKIE_NAME: str = "scamsieve_session"
    DEBUG: bool = os.getenv("DEBUG", "True") == "True"
    ALLOWED_ORIGINS: list = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
        if origin.strip()
    ]


settings = Settings()

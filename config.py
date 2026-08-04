import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

    # Database Configuration
    DATABASE_URL = os.getenv("DATABASE_URL")
    if DATABASE_URL:
        SQLALCHEMY_DATABASE_URI = DATABASE_URL
    else:
        db_path = os.path.join(BASE_DIR, "database", "users.db")
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AUTO_CREATE_SCHEMA = os.getenv("AUTO_CREATE_SCHEMA", "True").lower() in ("true", "1", "t")

    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit

    # Public Lookup Configuration
    PUBLIC_LOOKUPS_ENABLED = os.getenv("PUBLIC_LOOKUPS_ENABLED", "True").lower() in ("true", "1", "t")
    PUBLIC_LOOKUP_TIMEOUT_SECONDS = int(os.getenv("PUBLIC_LOOKUP_TIMEOUT_SECONDS", "3"))
    PUBLIC_LOOKUP_MAX_LOOKUPS = int(os.getenv("PUBLIC_LOOKUP_MAX_LOOKUPS", "5"))

    # Debug Configuration
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

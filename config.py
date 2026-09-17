import os
import re
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    _raw_secret = os.getenv("SECRET_KEY") or os.getenv("PHISHING_DETECTOR_SECRET_KEY")
    _testing = (
        os.getenv("TESTING", "False").lower() in ("true", "1", "t")
        or "pytest" in os.getenv("_", "")
        or "PYTEST_CURRENT_TEST" in os.environ
        or any("pytest" in arg.lower() or "unittest" in arg.lower() for arg in os.sys.argv)
    )
    _debug = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

    if not _raw_secret:
        if _testing or _debug:
            SECRET_KEY = "dev-secret-key-change-in-production"
        else:
            raise RuntimeError("SECRET_KEY or PHISHING_DETECTOR_SECRET_KEY environment variable must be set in production.")
    else:
        SECRET_KEY = _raw_secret

    WTF_CSRF_ENABLED = os.getenv("WTF_CSRF_ENABLED", "True").lower() in ("true", "1", "t")
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "True").lower() in ("true", "1", "t")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Secure Cookie & Session Settings
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", str(not (_debug or _testing))).lower() in ("true", "1", "t")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 7200  # 2 Hours lifetime in seconds
    SESSION_REFRESH_EACH_REQUEST = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_SAMESITE = "Lax"

    # Database Configuration
    _db_url = os.getenv("DATABASE_URL")
    if _db_url:
        if _db_url.startswith("sqlite:///") and not os.path.isabs(_db_url.replace("sqlite:///", "")):
            rel_path = _db_url.replace("sqlite:///", "")
            abs_db_path = os.path.abspath(os.path.join(BASE_DIR, rel_path))
            os.makedirs(os.path.dirname(abs_db_path), exist_ok=True)
            normalized_abs_path = abs_db_path.replace("\\", "/")
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{normalized_abs_path}"
        else:
            SQLALCHEMY_DATABASE_URI = _db_url
    else:
        db_path = os.path.abspath(os.path.join(BASE_DIR, "database", "users.db"))
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        normalized_db_path = db_path.replace("\\", "/")
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{normalized_db_path}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    _auto_create_env = os.getenv("AUTO_CREATE_SCHEMA") or os.getenv("PHISHING_DETECTOR_AUTO_CREATE_SCHEMA") or "False"
    AUTO_CREATE_SCHEMA = _auto_create_env.lower() in ("true", "1", "t")

    # Tenant boundaries and public-scanner routing
    DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "default").strip().lower()
    PUBLIC_SCAN_TENANT_ID = os.getenv("PUBLIC_SCAN_TENANT_ID", DEFAULT_TENANT_ID).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", DEFAULT_TENANT_ID):
        raise RuntimeError("DEFAULT_TENANT_ID must contain 1-64 lowercase letters, numbers, underscores, or hyphens.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", PUBLIC_SCAN_TENANT_ID):
        raise RuntimeError("PUBLIC_SCAN_TENANT_ID must contain 1-64 lowercase letters, numbers, underscores, or hyphens.")

    # Authentication and evidence retention
    MFA_REQUIRED_FOR_STAFF = os.getenv("MFA_REQUIRED_FOR_STAFF", "False").lower() in ("true", "1", "t")
    MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "Guardly")
    EVIDENCE_RETENTION_DAYS = int(os.getenv("EVIDENCE_RETENTION_DAYS", "90"))
    if EVIDENCE_RETENTION_DAYS < 1:
        raise RuntimeError("EVIDENCE_RETENTION_DAYS must be at least one day.")

    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(BASE_DIR, "uploads"))
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit

    # Public Lookup Configuration
    PUBLIC_LOOKUPS_ENABLED = os.getenv("PUBLIC_LOOKUPS_ENABLED", "True").lower() in ("true", "1", "t")
    PUBLIC_LOOKUP_TIMEOUT_SECONDS = int(os.getenv("PUBLIC_LOOKUP_TIMEOUT_SECONDS", "3"))
    PUBLIC_LOOKUP_MAX_LOOKUPS = int(os.getenv("PUBLIC_LOOKUP_MAX_LOOKUPS", "5"))

    # Geolocation Subsystem Configuration
    GEOLOCATION_CITY_PATH = os.getenv("GEOLOCATION_CITY_PATH", os.path.join(BASE_DIR, "data", "GeoLite2-City.mmdb"))
    GEOLOCATION_ASN_PATH = os.getenv("GEOLOCATION_ASN_PATH", os.path.join(BASE_DIR, "data", "GeoLite2-ASN.mmdb"))
    GEOLOCATION_CACHE_MAX_SIZE = int(os.getenv("GEOLOCATION_CACHE_MAX_SIZE", "10000"))
    GEOLOCATION_CACHE_TTL = int(os.getenv("GEOLOCATION_CACHE_TTL", "3600"))
    GEOLOCATION_CACHE_NEGATIVE_TTL = int(os.getenv("GEOLOCATION_CACHE_NEGATIVE_TTL", "300"))
    GEOLOCATION_FALLBACK_ENABLED = os.getenv("GEOLOCATION_FALLBACK_ENABLED", "True").lower() in ("true", "1", "t")
    GEOLOCATION_FALLBACK_PROVIDER = os.getenv("GEOLOCATION_FALLBACK_PROVIDER", "ip-api")
    GEOLOCATION_FALLBACK_API_KEY = os.getenv("GEOLOCATION_FALLBACK_API_KEY", "")
    GEOLOCATION_FALLBACK_TIMEOUT = float(os.getenv("GEOLOCATION_FALLBACK_TIMEOUT", "2.0"))

    # SMTP Receiver Configuration
    SMTP_HOST = os.getenv("SMTP_HOST", "127.0.0.1")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "2525"))
    MAIL_STORAGE_PATH = os.getenv("MAIL_STORAGE_PATH", os.path.join(BASE_DIR, "received_emails"))
    MAX_MESSAGE_SIZE = int(os.getenv("MAX_MESSAGE_SIZE", str(10 * 1024 * 1024)))

    # Consumer Analysis Safeguards & Limits
    MAX_ATTACHMENTS = int(os.getenv("MAX_ATTACHMENTS", "20"))
    MAX_URLS = int(os.getenv("MAX_URLS", "100"))
    MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))
    MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
    MAX_SCAN_TIME = int(os.getenv("MAX_SCAN_TIME", "30"))
    MAX_PDF_SIZE = int(os.getenv("MAX_PDF_SIZE", str(10 * 1024 * 1024)))
    MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "25000000"))
    SMTP_ENABLED = os.getenv("SMTP_ENABLED", "False").lower() in ("true", "1", "t")
    GUEST_RETENTION_HOURS = int(os.getenv("GUEST_RETENTION_HOURS", "24"))

    # Debug Configuration
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

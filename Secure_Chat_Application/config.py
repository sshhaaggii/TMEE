"""
config.py — Application configuration
Loads from environment variables with secure defaults and Supabase PostgreSQL integration.
"""
import os
from datetime import timedelta
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Base directory of the Secure_Chat_Application
BASE_DIR: str = os.path.abspath(os.path.dirname(__file__))

# Load .env file automatically
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    # ── Core Security ──────────────────────────────────────────
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY",
        "dev-only-change-me-in-production-use-a-long-random-secret"
    )

    # ── Local SQLite Storage (Migration & Fallback) ────────────
    BASE_DIR: str = BASE_DIR
    DATABASE: str = os.path.join(BASE_DIR, "database", "chat.db")

    # ── Supabase PostgreSQL Database Configuration ─────────────
    DATABASE_URL: str = os.environ.get("DATABASE_URL", "").strip()

    SUPABASE_DB_HOST: str     = os.environ.get("SUPABASE_DB_HOST", "").strip()
    SUPABASE_DB_PORT: int     = int(os.environ.get("SUPABASE_DB_PORT", "5432") or "5432")
    SUPABASE_DB_NAME: str     = os.environ.get("SUPABASE_DB_NAME", "postgres").strip()
    SUPABASE_DB_USER: str     = os.environ.get("SUPABASE_DB_USER", "postgres").strip()
    SUPABASE_DB_PASSWORD: str = os.environ.get("SUPABASE_DB_PASSWORD", "").strip()
    SUPABASE_DB_SSLMODE: str  = os.environ.get("SUPABASE_DB_SSLMODE", "require").strip()

    # Supabase REST API & Keys (strictly backend, never sent to frontend)
    SUPABASE_URL: str              = os.environ.get("SUPABASE_URL", "").strip()
    SUPABASE_ANON_KEY: str         = os.environ.get("SUPABASE_ANON_KEY", "").strip()
    SUPABASE_SERVICE_ROLE_KEY: str = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()

    # Fallback to local SQLite when Supabase credentials are not yet set
    USE_SQLITE_FALLBACK: bool = os.environ.get("USE_SQLITE_FALLBACK", "True").lower() in ("true", "1", "yes")

    # ── Session security ───────────────────────────────────────
    SESSION_COOKIE_HTTPONLY: bool  = True
    SESSION_COOKIE_SAMESITE: str   = "Lax"
    SESSION_COOKIE_SECURE:   bool  = False   # Set True behind HTTPS in production
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=12)

    # ── CSRF ───────────────────────────────────────────────────
    WTF_CSRF_TIME_LIMIT: int = 3600   # seconds

    # ── Validation rules ───────────────────────────────────────
    USERNAME_MIN: int = 3
    USERNAME_MAX: int = 20
    PASSWORD_MIN: int = 8

    @classmethod
    def is_supabase_configured(cls) -> bool:
        """Return True if any valid Supabase connection information is provided."""
        if cls.DATABASE_URL and "your_supabase" not in cls.DATABASE_URL and "your_project_ref" not in cls.DATABASE_URL:
            return True
        if cls.SUPABASE_DB_HOST and cls.SUPABASE_DB_PASSWORD:
            return True
        return False

    @classmethod
    def get_postgres_dsn(cls) -> str:
        """
        Return the PostgreSQL connection DSN string for Supabase.
        Prefers DATABASE_URL if available; otherwise builds from individual params.
        """
        if cls.DATABASE_URL and "your_supabase" not in cls.DATABASE_URL:
            # Normalize prefix if needed (e.g. postgres:// -> postgresql://)
            url = cls.DATABASE_URL
            if url.startswith("postgres://"):
                url = "postgresql://" + url[len("postgres://"):]
            if "sslmode=" not in url:
                delim = "&" if "?" in url else "?"
                url = f"{url}{delim}sslmode={cls.SUPABASE_DB_SSLMODE}"
            return url

        if cls.SUPABASE_DB_HOST and cls.SUPABASE_DB_PASSWORD:
            encoded_pw = quote_plus(cls.SUPABASE_DB_PASSWORD)
            encoded_user = quote_plus(cls.SUPABASE_DB_USER)
            return (
                f"postgresql://{encoded_user}:{encoded_pw}@"
                f"{cls.SUPABASE_DB_HOST}:{cls.SUPABASE_DB_PORT}/"
                f"{cls.SUPABASE_DB_NAME}?sslmode={cls.SUPABASE_DB_SSLMODE}"
            )
        return ""


class DevelopmentConfig(Config):
    DEBUG: bool = True


class ProductionConfig(Config):
    DEBUG: bool = False
    SESSION_COOKIE_SECURE: bool = True


config = DevelopmentConfig()

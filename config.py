"""
Configuration settings for Sentinel-X Platform.
Loads database and application settings from environment variables.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration."""

    # Database settings
    DATABASE_HOST = os.getenv("DATABASE_HOST", "localhost")
    DATABASE_PORT = int(os.getenv("DATABASE_PORT", "5432"))
    DATABASE_NAME = os.getenv("DATABASE_NAME", "sentinel_db")
    DATABASE_USER = os.getenv("DATABASE_USER", "sentinel")
    DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "sentinel_pass")

    # Connection pool settings
    DATABASE_MIN_CONNECTIONS = int(os.getenv("DATABASE_MIN_CONNECTIONS", "1"))
    DATABASE_MAX_CONNECTIONS = int(os.getenv("DATABASE_MAX_CONNECTIONS", "10"))

    # Application settings
    FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

    # Traffic engine settings
    PACKET_BUFFER_LIMIT = int(os.getenv("PACKET_BUFFER_LIMIT", "500"))

    @classmethod
    def get_database_url(cls):
        """Get PostgreSQL connection URL."""
        return f"postgresql://{cls.DATABASE_USER}:{cls.DATABASE_PASSWORD}@{cls.DATABASE_HOST}:{cls.DATABASE_PORT}/{cls.DATABASE_NAME}"

    @classmethod
    def get_database_params(cls):
        """Get database connection parameters as dict."""
        return {
            "host": cls.DATABASE_HOST,
            "port": cls.DATABASE_PORT,
            "database": cls.DATABASE_NAME,
            "user": cls.DATABASE_USER,
            "password": cls.DATABASE_PASSWORD,
        }

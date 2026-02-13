import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "rednerve-dev-key-change-in-prod")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///rednerve.db")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")

    # Beacon settings
    BEACON_SECRET = os.getenv("BEACON_SECRET", "rednerve-beacon-key")
    BEACON_CHECKIN_INTERVAL = int(os.getenv("BEACON_CHECKIN_INTERVAL", "5"))  # seconds
    BEACON_TASK_TIMEOUT = int(os.getenv("BEACON_TASK_TIMEOUT", "300"))  # seconds

    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "9999"))

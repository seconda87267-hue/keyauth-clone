import os
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()

# Default to SQLite for easy testing; set DATABASE_URL env var for MySQL/Postgres
BASE_DIR = Path(__file__).parent
SQLITE_PATH = str(BASE_DIR / "keyauth.db")

# URL-encode the path to handle spaces
_env_db = os.environ.get("DATABASE_URL", "")
DATABASE_URL = _env_db if _env_db else f"sqlite:///{quote(SQLITE_PATH)}"

# On Netlify/Railway/Render, you MUST set DATABASE_URL in env vars
# SQLite only works locally. Get free Postgres at https://supabase.com
IS_SERVERLESS = os.environ.get("NETLIFY", "") == "true"
if IS_SERVERLESS and not _env_db:
    import warnings
    warnings.warn(
        "DATABASE_URL not set! SQLite does NOT work on serverless platforms. "
        "Set DATABASE_URL to a PostgreSQL connection string."
    )
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-very-long-random-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
RATE_LIMIT = "5/minute"

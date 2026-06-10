import os
from dotenv import load_dotenv

load_dotenv()

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
API_BASE_URL = os.getenv("API_BASE_URL", "https://keyauth-clone-production-22ff.up.railway.app")
ADMIN_KEY = os.getenv("ADMIN_KEY", "admin123")
ALLOWED_ROLES = os.getenv("ALLOWED_ROLES", "Admin,Developer").split(",")

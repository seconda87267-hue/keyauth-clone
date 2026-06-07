"""
Netlify Function entry point.
Wraps the FastAPI app with Mangum for serverless deployment.
"""
import os
import sys

# Ensure the server root is on the path so imports work
_wd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _wd not in sys.path:
    sys.path.insert(0, _wd)

from main import app
from database.database import init_db

# Run DB init on cold start
init_db()

# Mangum adapter converts FastAPI ASGI to AWS Lambda / Netlify Functions format
from mangum import Mangum
handler = Mangum(app)

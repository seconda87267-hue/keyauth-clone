import uvicorn
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from config import SECRET_KEY
from database.database import init_db
from auth.rate_limiter import limiter
from routes.auth_routes import router as auth_router
from routes.license_routes import router as license_router
from routes.admin_routes import router as admin_router

app = FastAPI(
    title="KeyAuth Clone API",
    description="License Key + HWID Authentication System",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS - allows your domain + localhost to access the API
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8002,http://127.0.0.1:8002"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session middleware - set secure=True only if using HTTPS
SESSION_SECURE = os.getenv("SESSION_SECURE", "false").lower() == "true"
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="keyauth_session",
    same_site="lax",
    https_only=SESSION_SECURE,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router)
app.include_router(license_router)
app.include_router(admin_router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return RedirectResponse(url="/admin/login")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "Internal server error"}
    )


# Export for Mangum / Netlify Functions
handler = None
try:
    from mangum import Mangum
    handler = Mangum(app)
except ImportError:
    pass

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

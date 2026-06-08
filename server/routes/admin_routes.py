from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pathlib import Path
import secrets
import string
import hashlib
import jinja2

from database.database import get_db
from database.models import License, Log, SessionToken, Application
from auth.rate_limiter import limiter

router = APIRouter(prefix="/admin", tags=["admin"])
_base = Path(__file__).resolve().parent.parent
_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_base / "admin" / "templates")),
    autoescape=jinja2.select_autoescape(),
    cache_size=0
)
templates = Jinja2Templates(env=_jinja_env)


def login_required(request: Request):
    if not request.session.get("admin_logged_in"):
        raise HTTPException(status_code=303, detail="Not authorized")


@router.get("/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def admin_login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    from config import ADMIN_USERNAME, ADMIN_PASSWORD
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        request.session["admin_logged_in"] = True
        return RedirectResponse(url="/admin/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"})


@router.get("/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    login_required(request)
    total_licenses = db.query(License).count()
    active_licenses = db.query(License).filter(
        License.banned == False,
        (License.expires == None) | (License.expires > datetime.utcnow())
    ).count()
    banned_licenses = db.query(License).filter(License.banned == True).count()
    bound_licenses = db.query(License).filter(License.hwid != None).count()
    total_apps = db.query(Application).count()
    recent_logs = db.query(Log).order_by(desc(Log.timestamp)).limit(10).all()
    apps = db.query(Application).all()
    return templates.TemplateResponse(request, "dashboard.html", {
        "total": total_licenses, "active": active_licenses,
        "banned": banned_licenses, "bound": bound_licenses,
        "total_apps": total_apps, "logs": recent_logs, "apps": apps
    })


# ---------------------------------------------------------------------------
# LICENSES
# ---------------------------------------------------------------------------
@router.get("/licenses", response_class=HTMLResponse)
def admin_licenses(request: Request, page: int = 1, db: Session = Depends(get_db)):
    login_required(request)
    per_page = 50
    offset = (page - 1) * per_page
    licenses = db.query(License).order_by(desc(License.created_at)).offset(offset).limit(per_page).all()
    total = db.query(License).count()
    total_pages = (total + per_page - 1) // per_page
    apps = db.query(Application).all()
    return templates.TemplateResponse(request, "licenses.html", {
        "licenses": licenses, "page": page, "total_pages": total_pages,
        "total": total, "now": datetime.utcnow(), "apps": apps
    })


@router.post("/generate")
def admin_generate(request: Request, count: int = Form(1), expiry_days: int = Form(30),
                   app_id: int = Form(0), db: Session = Depends(get_db)):
    login_required(request)

    def gen_key():
        chars = string.ascii_uppercase + string.digits
        return "-".join("".join(secrets.choice(chars) for _ in range(6)) for _ in range(3))

    keys = []
    for _ in range(count):
        key = gen_key()
        expiry = datetime.utcnow() + timedelta(days=expiry_days) if expiry_days > 0 else None
        app_id_val = app_id if app_id > 0 else None
        lic = License(license_key=key, expires=expiry, app_id=app_id_val)
        db.add(lic)
        keys.append(key)
    db.commit()
    return RedirectResponse(url="/admin/licenses", status_code=303)


@router.post("/delete-license/{license_id}")
def admin_delete_license(request: Request, license_id: int, db: Session = Depends(get_db)):
    login_required(request)
    lic = db.query(License).filter(License.id == license_id).first()
    if lic:
        db.query(SessionToken).filter(SessionToken.license_id == lic.id).delete()
        db.delete(lic)
        db.commit()
    return RedirectResponse(url="/admin/licenses", status_code=303)


@router.post("/ban/{license_id}")
def admin_toggle_ban(request: Request, license_id: int, db: Session = Depends(get_db)):
    login_required(request)
    lic = db.query(License).filter(License.id == license_id).first()
    if lic:
        lic.banned = not lic.banned
        log = Log(license_key=lic.license_key, action="BAN_TOGGLE", detail=f"Banned={lic.banned}")
        db.add(log)
        db.commit()
    return RedirectResponse(url="/admin/licenses", status_code=303)


@router.post("/reset-hwid/{license_id}")
def admin_reset_hwid(request: Request, license_id: int, db: Session = Depends(get_db)):
    login_required(request)
    lic = db.query(License).filter(License.id == license_id).first()
    if lic:
        old_hwid = lic.hwid
        lic.hwid = None
        log = Log(license_key=lic.license_key, action="HWID_RESET", detail=f"HWID cleared (was: {old_hwid[:16] if old_hwid else 'None'}...)")
        db.add(log)
        db.commit()
    return RedirectResponse(url="/admin/licenses", status_code=303)


# ---------------------------------------------------------------------------
# APPLICATIONS
# ---------------------------------------------------------------------------
@router.get("/applications", response_class=HTMLResponse)
def admin_applications(request: Request, db: Session = Depends(get_db)):
    login_required(request)
    apps = db.query(Application).order_by(desc(Application.created_at)).all()
    app_data = []
    for a in apps:
        lic_count = db.query(License).filter(License.app_id == a.id).count()
        app_data.append({**{k: getattr(a, k) for k in ("id","name","api_key","api_secret","created_at")}, "lic_count": lic_count})
    return templates.TemplateResponse(request, "applications.html", {"apps": app_data})


@router.post("/applications/create")
def admin_create_app(request: Request, name: str = Form(...), db: Session = Depends(get_db)):
    login_required(request)
    name = name.strip()
    if not name:
        return RedirectResponse(url="/admin/applications", status_code=303)
    api_key = secrets.token_hex(16).upper()
    api_secret = secrets.token_hex(32)
    app = Application(name=name, api_key=api_key, api_secret=api_secret)
    db.add(app)
    log = Log(action="APP_CREATE", detail=f"Application '{name}' created")
    db.add(log)
    db.commit()
    return RedirectResponse(url="/admin/applications", status_code=303)


@router.post("/applications/delete/{app_id}")
def admin_delete_app(request: Request, app_id: int, db: Session = Depends(get_db)):
    login_required(request)
    app = db.query(Application).filter(Application.id == app_id).first()
    if app:
        db.query(License).filter(License.app_id == app.id).update({"app_id": None})
        db.delete(app)
        log = Log(action="APP_DELETE", detail=f"Application '{app.name}' deleted")
        db.add(log)
        db.commit()
    return RedirectResponse(url="/admin/applications", status_code=303)


@router.get("/applications/credentials/{app_id}", response_class=HTMLResponse)
def admin_app_credentials(request: Request, app_id: int, db: Session = Depends(get_db)):
    login_required(request)
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        return RedirectResponse(url="/admin/applications", status_code=303)
    app_licenses = db.query(License).filter(License.app_id == app.id).order_by(desc(License.created_at)).limit(50).all()
    base_url = str(request.base_url).rstrip("/")
    return templates.TemplateResponse(request, "credentials.html", {
        "app": app, "lic_count": len(app_licenses), "licenses": app_licenses,
        "now": datetime.utcnow(), "base_url": base_url
    })


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------
@router.get("/users", response_class=HTMLResponse)
def admin_users(request: Request, page: int = 1, db: Session = Depends(get_db)):
    login_required(request)
    per_page = 50
    offset = (page - 1) * per_page
    users = (
        db.query(License, Application)
        .outerjoin(Application, License.app_id == Application.id)
        .filter(License.hwid != None)
        .order_by(desc(License.last_login))
        .offset(offset)
        .limit(per_page)
        .all()
    )
    total = db.query(License).filter(License.hwid != None).count()
    total_pages = (total + per_page - 1) // per_page

    # Get latest IP for each license from session tokens
    user_data = []
    for lic, app in users:
        last_session = (
            db.query(SessionToken.ip_address)
            .filter(SessionToken.license_id == lic.id)
            .order_by(desc(SessionToken.created_at))
            .first()
        )
        ip = last_session[0] if last_session else "-"
        user_data.append((lic, app, ip))

    return templates.TemplateResponse(request, "users.html", {
        "users": user_data, "page": page, "total_pages": total_pages,
        "total": total, "now": datetime.utcnow()
    })


# ---------------------------------------------------------------------------
# LOGS
# ---------------------------------------------------------------------------
@router.get("/logs", response_class=HTMLResponse)
def admin_logs(request: Request, page: int = 1, db: Session = Depends(get_db)):
    login_required(request)
    per_page = 100
    offset = (page - 1) * per_page
    logs = db.query(Log).order_by(desc(Log.timestamp)).offset(offset).limit(per_page).all()
    total = db.query(Log).count()
    total_pages = (total + per_page - 1) // per_page
    return templates.TemplateResponse(request, "logs.html", {
        "logs": logs, "page": page, "total_pages": total_pages, "total": total
    })


# ---------------------------------------------------------------------------
# ADMIN CREDENTIALS
# ---------------------------------------------------------------------------
@router.get("/credentials", response_class=HTMLResponse)
def admin_credentials_page(request: Request):
    login_required(request)
    from config import ADMIN_USERNAME, ADMIN_PASSWORD
    return templates.TemplateResponse(request, "credentials_admin.html", {
        "admin_user": ADMIN_USERNAME, "admin_pass": ADMIN_PASSWORD, "saved": False
    })


@router.post("/credentials", response_class=HTMLResponse)
def admin_credentials_save(request: Request, username: str = Form(...), password: str = Form(...)):
    login_required(request)
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        content = env_path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        new_lines = []
        has_user, has_pass = False, False
        for line in lines:
            if line.startswith("ADMIN_USERNAME="):
                new_lines.append(f"ADMIN_USERNAME={username}\n")
                has_user = True
            elif line.startswith("ADMIN_PASSWORD="):
                new_lines.append(f"ADMIN_PASSWORD={password}\n")
                has_pass = True
            else:
                new_lines.append(line)
        if not has_user:
            new_lines.append(f"ADMIN_USERNAME={username}\n")
        if not has_pass:
            new_lines.append(f"ADMIN_PASSWORD={password}\n")
        env_path.write_text("".join(new_lines), encoding="utf-8")
    return templates.TemplateResponse(request, "credentials_admin.html", {
        "admin_user": username, "admin_pass": password, "saved": True
    })


@router.get("/logout")
def admin_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/admin/login", status_code=303)

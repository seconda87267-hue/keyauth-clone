from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from database.database import get_db
from database.models import License, SessionToken, Log
from auth.jwt_handler import create_session_token, decode_access_token
from auth.encryption import encrypt_data, decrypt_data, sign_request, verify_signature
from auth.rate_limiter import limiter

router = APIRouter(prefix="/api", tags=["auth"])


class LoginRequest(BaseModel):
    license: str
    hwid: str
    encrypted: bool = False


class ValidateRequest(BaseModel):
    token: str


class HeartbeatRequest(BaseModel):
    token: str


class ResetHWIDRequest(BaseModel):
    license: str
    admin_key: str


def log_action(db: Session, license_key: str | None, action: str, detail: str | None, ip: str | None):
    log = Log(license_key=license_key, action=action, detail=detail, ip_address=ip)
    db.add(log)
    db.commit()


@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, data: LoginRequest, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    license_key = data.license.strip().upper()
    hwid = data.hwid.strip()

    if data.encrypted:
        decrypted = decrypt_data(data.license)
        if decrypted:
            license_key = decrypted.get("license", license_key)
            hwid = decrypted.get("hwid", hwid)

    lic = db.query(License).filter(License.license_key == license_key).first()

    if not lic:
        log_action(db, license_key, "LOGIN_FAIL", "License not found", ip)
        return {"success": False, "message": "Invalid license key"}

    if lic.banned:
        log_action(db, license_key, "LOGIN_FAIL", "Banned license", ip)
        return {"success": False, "message": "License is banned"}

    if lic.expires and lic.expires < datetime.now(timezone.utc).replace(tzinfo=None):
        log_action(db, license_key, "LOGIN_FAIL", "Expired license", ip)
        return {"success": False, "message": "License has expired"}

    if lic.hwid is None:
        existing = db.query(License).filter(License.hwid == hwid, License.id != lic.id).first()
        if existing:
            log_action(db, license_key, "HWID_BIND_FAIL", f"HWID already bound to {existing.license_key}", ip)
            return {"success": False, "message": "This HWID is already bound to another license key"}
        lic.hwid = hwid
        lic.hwid_bind_date = datetime.now(timezone.utc).replace(tzinfo=None)
        lic.ip_address = ip
        db.commit()
        log_action(db, license_key, "HWID_BIND", f"Bound HWID: {hwid[:16]}...", ip)
    elif lic.hwid != hwid:
        log_action(db, license_key, "LOGIN_FAIL", "HWID mismatch", ip)
        return {"success": False, "message": "HWID mismatch - this key is bound to another machine"}

    lic.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    lic.ip_address = ip
    token = create_session_token(lic.id, license_key)

    session_expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=24)
    session = SessionToken(license_id=lic.id, token=token, expires_at=session_expiry, ip_address=ip)
    db.add(session)
    db.commit()

    log_action(db, license_key, "LOGIN_OK", "Login successful", ip)

    return {
        "success": True,
        "token": token,
        "expires": lic.expires.isoformat() if lic.expires else None,
        "key_type": lic.key_type,
        "prefix": lic.prefix,
        "message": "Authenticated successfully"
    }


@router.post("/validate")
def validate(data: ValidateRequest, db: Session = Depends(get_db)):
    payload = decode_access_token(data.token)
    if not payload:
        return {"success": False, "message": "Invalid or expired token"}

    session = db.query(SessionToken).filter(
        SessionToken.token == data.token,
        SessionToken.expires_at > datetime.now(timezone.utc).replace(tzinfo=None)
    ).first()

    if not session:
        return {"success": False, "message": "Session expired"}

    lic = db.query(License).filter(License.id == int(payload["sub"])).first()
    if not lic or lic.banned:
        return {"success": False, "message": "License invalid or banned"}

    if lic.expires and lic.expires < datetime.now(timezone.utc).replace(tzinfo=None):
        return {"success": False, "message": "License expired"}

    return {"success": True, "message": "Session valid"}


@router.post("/heartbeat")
def heartbeat(data: HeartbeatRequest, db: Session = Depends(get_db)):
    payload = decode_access_token(data.token)
    if not payload:
        return {"success": False, "message": "Invalid token"}

    session = db.query(SessionToken).filter(
        SessionToken.token == data.token
    ).first()

    if not session:
        return {"success": False, "message": "Session not found"}

    lic = db.query(License).filter(License.id == int(payload["sub"])).first()
    if not lic or lic.banned:
        return {"success": False, "message": "License invalid or banned"}

    if lic.expires and lic.expires < datetime.now(timezone.utc).replace(tzinfo=None):
        return {"success": False, "message": "License expired"}

    new_expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=24)
    session.expires_at = new_expiry
    lic.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    return {"success": True, "message": "Heartbeat received"}


@router.post("/reset")
def reset_hwid(data: ResetHWIDRequest, db: Session = Depends(get_db)):
    from config import ADMIN_PASSWORD
    if data.admin_key != ADMIN_PASSWORD:
        return {"success": False, "message": "Invalid admin key"}

    lic = db.query(License).filter(License.license_key == data.license.strip().upper()).first()
    if not lic:
        return {"success": False, "message": "License not found"}

    old_hwid = lic.hwid
    lic.hwid = None
    db.commit()

    log_action(db, data.license, "HWID_RESET", f"HWID cleared (was: {old_hwid[:16] if old_hwid else 'None'}...)", "admin")
    return {"success": True, "message": "HWID reset successfully"}

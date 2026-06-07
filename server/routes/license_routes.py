from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database.database import get_db
from database.models import License, Log, Variable

router = APIRouter(prefix="/api/license", tags=["license"])


class GenerateRequest(BaseModel):
    count: int = 1
    expiry_days: Optional[int] = 30
    note: Optional[str] = None


class BanRequest(BaseModel):
    license_key: str
    admin_key: str
    ban: bool = True


class RedeemRequest(BaseModel):
    license_key: str
    hwid: str


@router.post("/generate")
def generate_keys(data: GenerateRequest, db: Session = Depends(get_db)):
    import secrets
    import string

    def gen_key():
        chars = string.ascii_uppercase + string.digits
        return "-".join(
            "".join(secrets.choice(chars) for _ in range(6))
            for _ in range(3)
        )

    keys = []
    for _ in range(data.count):
        key = gen_key()
        expiry = None
        if data.expiry_days and data.expiry_days > 0:
            expiry = datetime.utcnow() + timedelta(days=data.expiry_days)

        lic = License(license_key=key, expires=expiry, note=data.note)
        db.add(lic)
        keys.append({"license_key": key, "expires": expiry.isoformat() if expiry else None})

    db.commit()
    return {"success": True, "count": len(keys), "keys": keys}


@router.post("/ban")
def ban_license(data: BanRequest, db: Session = Depends(get_db)):
    from config import ADMIN_PASSWORD
    if data.admin_key != ADMIN_PASSWORD:
        return {"success": False, "message": "Invalid admin key"}

    lic = db.query(License).filter(License.license_key == data.license_key.strip().upper()).first()
    if not lic:
        return {"success": False, "message": "License not found"}

    lic.banned = data.ban
    db.commit()

    action = "BANNED" if data.ban else "UNBANNED"
    log = Log(license_key=data.license_key, action=action, detail=f"Admin set ban={data.ban}")
    db.add(log)
    db.commit()

    return {"success": True, "message": f"License {'banned' if data.ban else 'unbanned'} successfully"}


@router.post("/redeem")
def redeem_key(data: RedeemRequest, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.license_key == data.license_key.strip().upper()).first()
    if not lic:
        return {"success": False, "message": "Invalid license key"}

    if lic.banned:
        return {"success": False, "message": "License is banned"}

    if lic.expires and lic.expires < datetime.utcnow():
        return {"success": False, "message": "License has expired"}

    if lic.hwid and lic.hwid != data.hwid:
        return {"success": False, "message": "HWID mismatch"}

    if not lic.hwid:
        lic.hwid = data.hwid
        db.commit()

    return {"success": True, "message": "License redeemed successfully", "expires": lic.expires.isoformat() if lic.expires else None}


@router.get("/info")
def license_info(license_key: str = Query(...), db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.license_key == license_key.strip().upper()).first()
    if not lic:
        return {"success": False, "message": "License not found"}

    return {
        "success": True,
        "license_key": lic.license_key,
        "hwid_locked": lic.hwid is not None,
        "banned": lic.banned,
        "expires": lic.expires.isoformat() if lic.expires else "never",
        "created_at": lic.created_at.isoformat() if lic.created_at else None,
        "last_login": lic.last_login.isoformat() if lic.last_login else None,
        "note": lic.note
    }

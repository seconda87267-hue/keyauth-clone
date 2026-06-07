from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRY_HOURS


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def create_session_token(license_id: int, license_key: str) -> str:
    return create_access_token({
        "sub": str(license_id),
        "license": license_key,
        "type": "session"
    })

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from database.database import Base


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    owner_id = Column(Integer, default=1)
    api_key = Column(String(64), unique=True, nullable=False)
    api_secret = Column(String(64), nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    app_id = Column(Integer, ForeignKey("applications.id"), nullable=True, index=True)
    license_key = Column(String(64), unique=True, nullable=False, index=True)
    hwid = Column(Text, nullable=True)
    hwid_bind_date = Column(DateTime, nullable=True)
    ip_address = Column(String(45), nullable=True)
    expires = Column(DateTime, nullable=True)
    banned = Column(Boolean, default=False)
    key_type = Column(String(16), default="regular")
    prefix = Column(String(16), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime, nullable=True)
    note = Column(Text, nullable=True)


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_id = Column(Integer, nullable=False)
    token = Column(String(256), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    license_key = Column(String(64), nullable=True)
    action = Column(String(64), nullable=False)
    detail = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, server_default=func.now())


class Variable(Base):
    __tablename__ = "variables"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    value = Column(Text, nullable=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="admin")

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DATABASE_URL

_engine = None
_SessionLocal = None
Base = declarative_base()


def _get_engine():
    global _engine
    if _engine is None:
        if not DATABASE_URL:
            raise RuntimeError(
                "DATABASE_URL is not set. "
                "For Netlify deployment, you MUST set DATABASE_URL in your Netlify env vars.\n"
                "Get a free PostgreSQL database at https://supabase.com\n"
                "Then set: DATABASE_URL=postgresql://user:pass@host:5432/postgres"
            )
        _engine = create_engine(
            DATABASE_URL,
            connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
        )
        if "sqlite" in DATABASE_URL:
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
    return _engine


def _get_session_local():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_get_engine())
    return _SessionLocal


def get_db():
    db = _get_session_local()()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=_get_engine())
    _run_migrations()


def _run_migrations():
    engine = _get_engine()
    dialect = engine.dialect.name

    def add_cols(table, cols):
        with engine.connect() as conn:
            for col_name, col_type in cols.items():
                try:
                    sql = f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"
                    if dialect != "sqlite":
                        sql = sql.replace("ADD COLUMN", "ADD COLUMN IF NOT EXISTS")
                    conn.execute(text(sql))
                    conn.commit()
                except Exception:
                    conn.rollback()

    add_cols("licenses", {
        "key_type": "VARCHAR(16) DEFAULT 'regular'",
        "prefix": "VARCHAR(16)",
        "hwid_bind_date": "TIMESTAMP",
        "ip_address": "VARCHAR(45)",
        "hwid_lock": "INTEGER DEFAULT 1" if dialect == "sqlite" else "BOOLEAN DEFAULT TRUE",
        "created_by": "INTEGER",
    })

    add_cols("users", {
        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "created_by": "INTEGER DEFAULT 0",
    })

    add_cols("applications", {
        "owner_id": "INTEGER DEFAULT 1",
    })

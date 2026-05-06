"""
File: db.py
Purpose: Configure SQLAlchemy engine, sessions, and Base class.
Security: ORM parameter binding helps reduce SQL injection risk.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

def get_db():
    """Yield one short-lived DB session per request. Security: closes session after request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

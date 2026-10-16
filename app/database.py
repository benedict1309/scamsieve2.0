"""
Cau hinh ket noi database bang SQLAlchemy 2.0.
- Dev: SQLite (mac dinh, khong can cai server rieng)
- Production: PostgreSQL (chi can doi DATABASE_URL trong .env)
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.config import settings

# SQLite can them connect_args nay de dung duoc voi nhieu thread (FastAPI)
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Lop co so ma tat ca cac model se ke thua."""
    pass


def get_db():
    """
    Dependency cho FastAPI: mo 1 session DB cho moi request,
    tu dong dong lai sau khi request xu ly xong.
    Dung: def route(..., db: Session = Depends(get_db))
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

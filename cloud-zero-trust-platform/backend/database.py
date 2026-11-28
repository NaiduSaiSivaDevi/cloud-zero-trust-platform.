import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

configured_database_url = os.getenv("DATABASE_URL")
if os.getenv("VERCEL") == "1" and not configured_database_url:
    raise RuntimeError("Set DATABASE_URL to a persistent PostgreSQL database in Vercel project settings.")

DATABASE_URL = configured_database_url or "sqlite:///./cloud_zero_trust.db"
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

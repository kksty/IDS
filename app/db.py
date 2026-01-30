import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("IDS_DATABASE_URL")
if not DATABASE_URL:
    # try loading from .env for local development
    try:
        from dotenv import load_dotenv
        load_dotenv()
        DATABASE_URL = os.getenv("IDS_DATABASE_URL")
    except Exception:
        DATABASE_URL = None

if not DATABASE_URL:
    raise RuntimeError(
        "IDS_DATABASE_URL is not set. Configure PostgreSQL DSN, e.g. 'postgresql+psycopg2://user:pw@host:5432/ids'"
    )

# For PostgreSQL we don't need sqlite-specific connect args
connect_args = {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db():
    """Create database tables (idempotent)."""
    Base.metadata.create_all(bind=engine)

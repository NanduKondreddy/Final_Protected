# backend/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./dovtek.db")

# SQLite needs connect_args for thread safety
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Auto-migration helper for SQLite
def migrate_database():
    import sqlite3
    db_paths = ["dovtek.db", "shield.db"]
    for db_path in db_paths:
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(audit_records)")
                columns = [col[1] for col in cursor.fetchall()]
                # If audit_records table exists but columns are missing, alter the table
                if columns:
                    if "webhook_status" not in columns:
                        cursor.execute("ALTER TABLE audit_records ADD COLUMN webhook_status TEXT")
                    if "recommended_action" not in columns:
                        cursor.execute("ALTER TABLE audit_records ADD COLUMN recommended_action TEXT")
                    conn.commit()
                conn.close()
            except Exception as e:
                print(f"Migration error for {db_path}: {e}")

migrate_database()



def get_db():
    """Dependency injected into routes to provide a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
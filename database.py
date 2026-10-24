import os
import sqlite3
import logging
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger(__name__)

DB_PATH = BASE_DIR / "trustvault.db"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()


class PostgresConnectionWrapper:
    """
    Wraps a psycopg2 connection to provide a unified API with SQLite,
    allowing dictionary-like row access and converting '?' placeholders to '%s'.
    """
    def __init__(self, raw_conn):
        self.raw_conn = raw_conn

    def execute(self, sql, params=None):
        from psycopg2.extras import RealDictCursor
        pg_sql = sql.replace("?", "%s")
        cursor = self.raw_conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(pg_sql, params or ())
        return cursor

    def commit(self):
        self.raw_conn.commit()

    def rollback(self):
        self.raw_conn.rollback()

    def close(self):
        self.raw_conn.close()


def get_db_connection():
    """
    Returns a database connection.
    If DATABASE_URL is configured (Supabase PostgreSQL), uses psycopg2.
    Otherwise, falls back cleanly to local SQLite (trustvault.db).
    """
    db_url = os.environ.get("DATABASE_URL", "").strip()

    if db_url and not db_url.startswith("postgresql://postgres.your-project-ref"):
        try:
            import psycopg2
            raw_conn = psycopg2.connect(db_url)
            return PostgresConnectionWrapper(raw_conn)
        except Exception as e:
            logger.error(f"PostgreSQL connection error: {e}. Falling back to SQLite.")

    # SQLite Fallback
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def is_postgres() -> bool:
    """Checks if the active connection uses PostgreSQL."""
    db_url = os.environ.get("DATABASE_URL", "").strip()
    return bool(db_url and not db_url.startswith("postgresql://postgres.your-project-ref"))


def init_db():
    """
    Initializes tables and applies backward-compatible column migrations.
    Safely creates tables for users, documents, permissions, and audit logs.
    """
    conn = get_db_connection()
    use_pg = is_postgres()

    try:
        # 1. Users Table
        if use_pg:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user'
                        CHECK (role IN ('user', 'admin')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                        CHECK (role IN ('user', 'admin')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        # 2. Documents Table
        if use_pg:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    original_name VARCHAR(255) NOT NULL,
                    stored_name VARCHAR(255) NOT NULL UNIQUE,
                    storage_path TEXT,
                    sha256_hash VARCHAR(64) NOT NULL,
                    file_size INTEGER DEFAULT 0,
                    category VARCHAR(50) DEFAULT 'General',
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    storage_path TEXT,
                    sha256_hash TEXT NOT NULL,
                    file_size INTEGER DEFAULT 0,
                    category TEXT DEFAULT 'General',
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id)
                )
            """)

        # 3. Document Permissions Table (for Viewer / Cross-User Sharing)
        if use_pg:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS document_permissions (
                    id SERIAL PRIMARY KEY,
                    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    permission VARCHAR(20) NOT NULL DEFAULT 'READ'
                        CHECK (permission IN ('READ', 'EDIT')),
                    granted_by INTEGER REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (document_id, user_id)
                )
            """)
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS document_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    permission TEXT NOT NULL DEFAULT 'READ'
                        CHECK (permission IN ('READ', 'EDIT')),
                    granted_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (document_id, user_id),
                    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (granted_by) REFERENCES users(id)
                )
            """)

        # 4. Audit Logs Table
        if use_pg:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    action VARCHAR(50) NOT NULL,
                    document_name VARCHAR(255),
                    status VARCHAR(20) DEFAULT 'SUCCESS',
                    ip_address VARCHAR(45),
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    document_name TEXT,
                    status TEXT DEFAULT 'SUCCESS',
                    ip_address TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

        # Backward compatibility column migrations for existing databases
        if use_pg:
            # PostgreSQL column migrations
            conn.execute("ALTER TABLE documents ADD COLUMN IF NOT EXISTS storage_path TEXT")
            conn.execute("ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_size INTEGER DEFAULT 0")
            conn.execute("ALTER TABLE documents ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'General'")
            conn.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'SUCCESS'")
            conn.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45)")
            conn.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT")
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user'")
        else:
            # Check and add missing columns to documents in SQLite
            cursor = conn.execute("PRAGMA table_info(documents)")
            existing_doc_cols = [row["name"] for row in cursor.fetchall()]
            if "storage_path" not in existing_doc_cols:
                conn.execute("ALTER TABLE documents ADD COLUMN storage_path TEXT")
            if "file_size" not in existing_doc_cols:
                conn.execute("ALTER TABLE documents ADD COLUMN file_size INTEGER DEFAULT 0")
            if "category" not in existing_doc_cols:
                conn.execute("ALTER TABLE documents ADD COLUMN category TEXT DEFAULT 'General'")

            # Check and add missing columns to audit_logs in SQLite
            cursor = conn.execute("PRAGMA table_info(audit_logs)")
            existing_audit_cols = [row["name"] for row in cursor.fetchall()]
            if "status" not in existing_audit_cols:
                conn.execute("ALTER TABLE audit_logs ADD COLUMN status TEXT DEFAULT 'SUCCESS'")
            if "ip_address" not in existing_audit_cols:
                conn.execute("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT")
            if "details" not in existing_audit_cols:
                conn.execute("ALTER TABLE audit_logs ADD COLUMN details TEXT")

            # Check and add missing role column to users in SQLite
            cursor = conn.execute("PRAGMA table_info(users)")
            existing_user_cols = [row["name"] for row in cursor.fetchall()]
            if "role" not in existing_user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")

        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    db_type = "Supabase PostgreSQL" if is_postgres() else "Local SQLite"
    print(f"TrustVault database ({db_type}) initialized successfully.")

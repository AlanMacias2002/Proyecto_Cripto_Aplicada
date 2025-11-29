import sqlite3
from typing import Optional
from utils.config import USERS_DB_PATH

CREATE_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);
"""

def _conn():
    return sqlite3.connect(USERS_DB_PATH)

def init_users_db():
    con = _conn()
    cur = con.cursor()
    cur.execute(CREATE_USERS_TABLE_SQL)
    con.commit()
    con.close()

def get_user(username: str) -> Optional[dict]:
    init_users_db()
    con = _conn()
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return dict(row) if row else None

def create_user(username: str, password_hash: str, role: str) -> bool:
    init_users_db()
    con = _conn()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        con.commit()
        return True
    except Exception:
        return False
    finally:
        con.close()

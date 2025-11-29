import os

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:8545")


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok=True)

ADMIN_DB_PATH = os.path.join(DATA_DIR, "blockaudit_admin.db")
OPERATIVE_DB_PATH = os.path.join(DATA_DIR, "blockaudit_operational.db")
USERS_DB_PATH = os.path.join(DATA_DIR, "blockaudit_users.db")

# Clave de sesión para autenticación en FastAPI/Starlette
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-secret-change-me")

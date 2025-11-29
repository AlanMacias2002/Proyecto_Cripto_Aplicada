import sqlite3
from typing import Optional, List, Dict

CREATE_ADMIN_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS admin_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL UNIQUE,
    entidad_real TEXT NOT NULL,
    timestamp TEXT,
    nonce TEXT,
    evento TEXT,
    detalles TEXT
);
"""

def _obtener_conexion(db_path: str):
    conn = sqlite3.connect(db_path)
    return conn

def _ensure_column(conn: sqlite3.Connection, table: str, column: str, col_type: str):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

def inicializar_admin_db(db_path: str):
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute(CREATE_ADMIN_TABLE_SQL)
    _ensure_column(conn, "admin_mappings", "evento", "TEXT")
    _ensure_column(conn, "admin_mappings", "detalles", "TEXT")
    conn.commit()
    conn.close()

def reset_admin_db(db_path: str):
    """
    Limpia la tabla administrativa. Se recomienda cuando Ganache se reinicia
    para evitar entradas huérfanas que ya no tienen tx válidas.
    """
    inicializar_admin_db(db_path)
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute("DELETE FROM admin_mappings")
    conn.commit()
    conn.close()

def insertar_mapeo_hash(
    db_path: str,
    hash_entidad: str,
    entidad_real: str,
    timestamp: str,
    nonce: str,
    evento: Optional[str] = None,
    detalles: Optional[str] = None,
):
    inicializar_admin_db(db_path)
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO admin_mappings(hash, entidad_real, timestamp, nonce, evento, detalles)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            entidad_real=excluded.entidad_real,
            timestamp=excluded.timestamp,
            nonce=excluded.nonce,
            evento=excluded.evento,
            detalles=excluded.detalles
        """,
        (hash_entidad, entidad_real, timestamp, nonce, evento, detalles)
    )
    conn.commit()
    conn.close()

def resolver_hash(db_path: str, hash_entidad: str) -> Optional[str]:
    inicializar_admin_db(db_path)
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute("SELECT entidad_real FROM admin_mappings WHERE hash = ?", (hash_entidad,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def listar_mapeos_admin(
    db_path: str,
    limit: int = 100,
    offset: int = 0,
    evento: Optional[str] = None,
    hash_val: Optional[str] = None,
    fecha: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    entidad_real: Optional[str] = None,
) -> List[Dict]:
    inicializar_admin_db(db_path)
    conn = _obtener_conexion(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    where = []
    params: List = []
    if evento:
        where.append("evento LIKE ?")
        params.append(f"%{evento}%")
    if hash_val:
        where.append("hash LIKE ?")
        params.append(f"%{hash_val}%")
    if entidad_real:
        where.append("entidad_real LIKE ?")
        params.append(f"%{entidad_real}%")
    if fecha:
        where.append("timestamp LIKE ?")
        params.append(f"%{fecha}%")
    if fecha_desde:
        where.append("timestamp >= ?")
        params.append(fecha_desde)
    if fecha_hasta:
        where.append("timestamp <= ?")
        params.append(fecha_hasta)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (
        "SELECT id, hash, entidad_real, timestamp, nonce, evento, detalles "
        "FROM admin_mappings"
        f"{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params.extend([int(limit), int(offset)])
    c.execute(sql, params)
    fetched = c.fetchall()
    rows = [{k: row[k] for k in row.keys()} for row in fetched]
    conn.close()
    return rows

import sqlite3
from typing import List, Dict, Optional

CREATE_OPERATIVE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS operative_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_entidad TEXT NOT NULL,
    evento TEXT,
    fecha TEXT,
    tx_hash TEXT,
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

def inicializar_operational_db(db_path: str):
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute(CREATE_OPERATIVE_TABLE_SQL)
    _ensure_column(conn, "operative_logs", "detalles", "TEXT")
    conn.commit()
    conn.close()

def reset_operational_db(db_path: str):
    """
    Limpia la tabla operativa. Útil cuando la cadena (Ganache) se reinicia y
    las transacciones previas dejan de existir.
    """
    inicializar_operational_db(db_path)
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute("DELETE FROM operative_logs")
    conn.commit()
    conn.close()

def insertar_log_operativo(
    db_path: str,
    hash_entidad: str,
    evento: str,
    fecha: str,
    tx_hash: str,
    detalles: Optional[str] = None,
):
    inicializar_operational_db(db_path)
    conn = _obtener_conexion(db_path)
    c = conn.cursor()
    c.execute(
        "INSERT INTO operative_logs(hash_entidad, evento, fecha, tx_hash, detalles) VALUES (?, ?, ?, ?, ?)",
        (hash_entidad, evento, fecha, tx_hash, detalles)
    )
    conn.commit()
    conn.close()

def listar_logs_operativos(
    db_path: str,
    limit: int = 100,
    offset: int = 0,
    evento: Optional[str] = None,
    hash_entidad: Optional[str] = None,
    fecha: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
) -> List[Dict]:
    inicializar_operational_db(db_path)
    conn = _obtener_conexion(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    where = []
    params: list = []
    if evento:
        where.append("evento LIKE ?")
        params.append(f"%{evento}%")
    if hash_entidad:
        where.append("hash_entidad LIKE ?")
        params.append(f"%{hash_entidad}%")
    if fecha:
        where.append("fecha LIKE ?")
        params.append(f"%{fecha}%")
    if fecha_desde:
        where.append("fecha >= ?")
        params.append(fecha_desde)
    if fecha_hasta:
        where.append("fecha <= ?")
        params.append(fecha_hasta)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (
        "SELECT id, hash_entidad, evento, fecha, tx_hash, detalles "
        "FROM operative_logs"
        f"{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params.extend([int(limit), int(offset)])
    c.execute(sql, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def obtener_log_por_tx(db_path: str, tx_hash: str) -> Optional[Dict]:
    inicializar_operational_db(db_path)
    conn = _obtener_conexion(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT id, hash_entidad, evento, fecha, tx_hash, detalles FROM operative_logs WHERE tx_hash = ? LIMIT 1",
        (tx_hash,),
    )
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def obtener_ultimo_log_por_hash(db_path: str, hash_entidad: str) -> Optional[Dict]:
    inicializar_operational_db(db_path)
    conn = _obtener_conexion(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT id, hash_entidad, evento, fecha, tx_hash, detalles FROM operative_logs WHERE hash_entidad = ? ORDER BY id DESC LIMIT 1",
        (hash_entidad,),
    )
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

from flask import Flask, render_template, request
from utils.config import OPERATIVE_DB_PATH, ADMIN_DB_PATH
from database.db_operational import listar_logs_operativos, obtener_log_por_tx, obtener_ultimo_log_por_hash
from database.db_admin import listar_mapeos_admin
from verification.verifier import build_expected_log, verify_tx_matches_expected
from datetime import datetime

def _norm_iso(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    s = s.replace(" ", "T")
    patterns = [
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for p in patterns:
        try:
            dt = datetime.strptime(s, p)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    return s

app = Flask(__name__, template_folder="templates")

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/operative")
def operative():
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    evento = request.args.get("evento") or None
    hash_q = request.args.get("hash") or None
    fecha = request.args.get("fecha") or None
    fecha_desde = _norm_iso(request.args.get("fecha_desde") or None)
    fecha_hasta = _norm_iso(request.args.get("fecha_hasta") or None)
    rows = listar_logs_operativos(
        OPERATIVE_DB_PATH,
        limit=limit,
        offset=offset,
        evento=evento,
        hash_entidad=hash_q,
        fecha=fecha,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )
    prev_offset = 0 if offset - limit < 0 else offset - limit
    next_offset = offset + limit
    return render_template(
        "operative.html",
        rows=rows,
        limit=limit,
        offset=offset,
        evento=evento or "",
        hash_val=hash_q or "",
        fecha=fecha or "",
        fecha_desde=fecha_desde or "",
        fecha_hasta=fecha_hasta or "",
        prev_offset=prev_offset,
        next_offset=next_offset,
    )

@app.get("/admin")
def admin():
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    evento = request.args.get("evento") or None
    hash_q = request.args.get("hash") or None
    fecha = request.args.get("fecha") or None
    entidad_real = request.args.get("entidad_real") or None
    fecha_desde = _norm_iso(request.args.get("fecha_desde") or None)
    fecha_hasta = _norm_iso(request.args.get("fecha_hasta") or None)
    rows = listar_mapeos_admin(
        ADMIN_DB_PATH,
        limit=limit,
        offset=offset,
        evento=evento,
        hash_val=hash_q,
        fecha=fecha,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
        entidad_real=entidad_real,
    )
    prev_offset = 0 if offset - limit < 0 else offset - limit
    next_offset = offset + limit
    return render_template(
        "admin.html",
        rows=rows,
        limit=limit,
        offset=offset,
        evento=evento or "",
        hash_val=hash_q or "",
        fecha=fecha or "",
        entidad_real=entidad_real or "",
        fecha_desde=fecha_desde or "",
        fecha_hasta=fecha_hasta or "",
        prev_offset=prev_offset,
        next_offset=next_offset,
    )

@app.get("/verify")
def verify_view():
    tx = request.args.get("tx")
    h = request.args.get("hash")
    context = {"tx": tx or "", "hash": h or ""}
    op_row = None
    if tx:
        op_row = obtener_log_por_tx(OPERATIVE_DB_PATH, tx)
        if not op_row:
            return render_template("verify.html", ok=False, message="No se encontró el registro operativo para el tx_hash proporcionado.", **context)
    elif h:
        op_row = obtener_ultimo_log_por_hash(OPERATIVE_DB_PATH, h)
        if not op_row:
            return render_template("verify.html", ok=False, message="No se encontró ningún registro operativo asociado a ese hash.", **context)
    else:
        return render_template("verify.html", ok=False, message="Debe proporcionar ?tx=... o ?hash=...", **context)

    # Cargar admin mapping para timestamp_hash
    from database.db_admin import inicializar_admin_db
    import sqlite3
    inicializar_admin_db(ADMIN_DB_PATH)
    con = sqlite3.connect(ADMIN_DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM admin_mappings WHERE hash = ? LIMIT 1", (op_row["hash_entidad"],))
    admin_row = cur.fetchone()
    con.close()
    admin_dict = dict(admin_row) if admin_row else None

    expected = build_expected_log(op_row, admin_dict)
    tx_hash = op_row["tx_hash"]
    result = verify_tx_matches_expected(tx_hash, expected)
    return render_template("verify.html", **result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

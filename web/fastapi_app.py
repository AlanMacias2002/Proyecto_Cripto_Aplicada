from fastapi import FastAPI, Query, HTTPException, Request, Body, Form
from pydantic import BaseModel, Field, field_validator
from typing import Any, Optional, Dict
import json
import threading, time, traceback
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from utils.config import OPERATIVE_DB_PATH, ADMIN_DB_PATH, SESSION_SECRET
from main import procesar_evento
from database.db_operational import listar_logs_operativos
from database.db_operational import listar_logs_operativos, obtener_log_por_tx, obtener_ultimo_log_por_hash, reset_operational_db
from database.db_admin import listar_mapeos_admin, resolver_hash, reset_admin_db
from verification.verifier import build_expected_log, verify_tx_matches_expected
from core.hasher import generar_hash_dinamico
from core.logger import construir_log
from blockchain.blockchain_client import BlockchainClient
from blockchain.transaction_manager import enviar_evento_a_blockchain
from database.db_operational import insertar_log_operativo
from database.db_admin import insertar_mapeo_hash
from utils.timestamp import ahora_iso
from core.event_generator import EVENTOS_TIPICOS
from starlette.middleware.sessions import SessionMiddleware
from database.db_users import init_users_db, get_user, create_user
import hashlib, hmac
import os
import re

app = FastAPI(title="BlockAudit API", version="1.0.0")
templates = Jinja2Templates(directory="web/templates")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
init_users_db()
default_admin_user = os.getenv("ADMIN_DEFAULT_USER")
default_admin_pass = os.getenv("ADMIN_DEFAULT_PASS")
if default_admin_user and default_admin_pass and not get_user(default_admin_user):
    def _hash_password(p: str) -> str:
        pepper = b"blockaudit-pepper"
        return hashlib.sha256(pepper + p.encode("utf-8")).hexdigest()
    create_user(default_admin_user, _hash_password(default_admin_pass), "admin")
    print(f"[AUTH] Usuario admin por defecto creado: {default_admin_user}")

EVENT_INTERVAL_SECONDS = 300  # 5 minutos
_scheduler_started = False
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

def _scheduler_loop():
    while True:
        try:
            resultado = procesar_evento()
            print(f"[SCHEDULER] Evento automático procesado hash={resultado['hash']} tx={resultado['tx_hash']}")
        except Exception as e:
            print("[SCHEDULER] Error procesando evento automático:", e)
            traceback.print_exc()
        time.sleep(EVENT_INTERVAL_SECONDS)

@app.on_event("startup")
def start_scheduler():
    global _scheduler_started
    # Limpiar bases al arranque del servidor para evitar entradas huérfanas
    try:
        reset_operational_db(OPERATIVE_DB_PATH)
        reset_admin_db(ADMIN_DB_PATH)
        print("[INIT] Bases limpiadas (operativa y administrativa).")
    except Exception as e:
        print(f"[INIT] No se pudieron limpiar las bases: {e}")
    if not _scheduler_started:
        t = threading.Thread(target=_scheduler_loop, daemon=True)
        t.start()
        _scheduler_started = True
        print(f"[SCHEDULER] Iniciado hilo de generación automática cada {EVENT_INTERVAL_SECONDS}s")

@app.get("/")
def root():
    # Redirige a la UI para login/registro
    return RedirectResponse(url="/ui")

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/operative")
def api_operative(request: Request, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    # Requiere sesión (user o admin)
    if not request.session.get("user"):
        raise HTTPException(status_code=401, detail="No autenticado")
    return listar_logs_operativos(OPERATIVE_DB_PATH, limit=limit, offset=offset)

@app.get("/api/admin")
def api_admin(request: Request, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No autorizado")
    return listar_mapeos_admin(ADMIN_DB_PATH, limit=limit, offset=offset)

@app.get("/api/admin/{hash_entidad}")
def api_admin_resolver(request: Request, hash_entidad: str):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No autorizado")
    entidad = resolver_hash(ADMIN_DB_PATH, hash_entidad)
    if entidad is None:
        raise HTTPException(status_code=404, detail="Hash no encontrado")
    return {"hash": hash_entidad, "entidad_real": entidad}

# --- HTML UI (FastAPI) ---
@app.get("/ui")
def ui_index(request: Request):
    return templates.TemplateResponse("fa_index.html", {"request": request, "user": request.session.get("user")})

@app.get("/ui/operative")
def ui_operative(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    evento: str | None = Query(None),
    hash: str | None = Query(None),
    fecha: str | None = Query(None),
    fecha_desde: str | None = Query(None),
    fecha_hasta: str | None = Query(None),
):
    if not request.session.get("user"):
        return RedirectResponse(url="/ui/login", status_code=302)
    fecha_desde = _norm_iso(fecha_desde)
    fecha_hasta = _norm_iso(fecha_hasta)
    rows = listar_logs_operativos(
        OPERATIVE_DB_PATH,
        limit=limit,
        offset=offset,
        evento=evento,
        hash_entidad=hash,
        fecha=fecha,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )
    prev_offset = 0 if offset - limit < 0 else offset - limit
    next_offset = offset + limit
    return templates.TemplateResponse(
        "fa_operative.html",
        {
            "request": request,
            "user": request.session.get("user"),
            "rows": rows,
            "limit": limit,
            "offset": offset,
            "prev_offset": prev_offset,
            "next_offset": next_offset,
            "evento": evento or "",
            "hash_val": hash or "",
            "fecha": fecha or "",
            "fecha_desde": fecha_desde or "",
            "fecha_hasta": fecha_hasta or "",
        },
    )

@app.get("/ui/admin")
def ui_admin(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    evento: str | None = Query(None),
    hash: str | None = Query(None),
    entidad_real: str | None = Query(None),
    fecha: str | None = Query(None),
    fecha_desde: str | None = Query(None),
    fecha_hasta: str | None = Query(None),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/ui/login", status_code=302)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No autorizado")
    fecha_desde = _norm_iso(fecha_desde)
    fecha_hasta = _norm_iso(fecha_hasta)
    rows = listar_mapeos_admin(
        ADMIN_DB_PATH,
        limit=limit,
        offset=offset,
        evento=evento,
        hash_val=hash,
        entidad_real=entidad_real,
        fecha=fecha,
        fecha_desde=fecha_desde,
        fecha_hasta=fecha_hasta,
    )
    prev_offset = 0 if offset - limit < 0 else offset - limit
    next_offset = offset + limit
    return templates.TemplateResponse(
        "fa_admin.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "limit": limit,
            "offset": offset,
            "prev_offset": prev_offset,
            "next_offset": next_offset,
            "evento": evento or "",
            "hash_val": hash or "",
            "entidad_real": entidad_real or "",
            "fecha": fecha or "",
            "fecha_desde": fecha_desde or "",
            "fecha_hasta": fecha_hasta or "",
        },
    )

@app.get("/ui/verify")
def ui_verify(request: Request, tx: str | None = Query(None), hash: str | None = Query(None)):
    if not request.session.get("user"):
        return RedirectResponse(url="/ui/login", status_code=302)
    context = {"request": request, "tx": tx or "", "hash": hash or ""}
    op_row = None
    if tx:
        op_row = obtener_log_por_tx(OPERATIVE_DB_PATH, tx)
        if not op_row:
            return templates.TemplateResponse("fa_verify.html", {**context, "ok": False, "message": "No se encontró el registro operativo para el tx_hash proporcionado."})
    elif hash:
        op_row = obtener_ultimo_log_por_hash(OPERATIVE_DB_PATH, hash)
        if not op_row:
            return templates.TemplateResponse("fa_verify.html", {**context, "ok": False, "message": "No se encontró ningún registro operativo asociado a ese hash."})
    else:
        return templates.TemplateResponse("fa_verify.html", {**context, "ok": False, "message": "Debe proporcionar ?tx=... o ?hash=..."})

    # Cargar admin mapping
    import sqlite3
    from database.db_admin import inicializar_admin_db
    inicializar_admin_db(ADMIN_DB_PATH)
    con = sqlite3.connect(ADMIN_DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM admin_mappings WHERE hash = ? LIMIT 1", (op_row["hash_entidad"],))
    admin_row = cur.fetchone()
    con.close()
    admin_dict = {k: admin_row[k] for k in admin_row.keys()} if admin_row else None

    expected = build_expected_log(op_row, admin_dict)
    tx_hash = op_row["tx_hash"]
    result = verify_tx_matches_expected(tx_hash, expected)
    expected_json_text = (
        json.dumps(result.get("expected_json"), indent=2, ensure_ascii=False)
        if result.get("expected_json") is not None
        else None
    )
    onchain_json_text = (
        json.dumps(result.get("onchain_json"), indent=2, ensure_ascii=False)
        if result.get("onchain_json") is not None
        else None
    )
    diffs_text = (
        json.dumps(result.get("diffs"), indent=2, ensure_ascii=False)
        if result.get("diffs") is not None
        else None
    )
    return templates.TemplateResponse(
        "fa_verify.html",
        {"request": request, "user": request.session.get("user"), **result, "expected_json_text": expected_json_text, "onchain_json_text": onchain_json_text, "diffs_text": diffs_text},
    )

# --- UI: login/register/logout ---
@app.get("/ui/login")
def ui_login(request: Request):
    return templates.TemplateResponse("fa_login.html", {"request": request, "error": None})

@app.post("/ui/login")
def ui_login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)
    def _hash_password(p: str) -> str:
        pepper = b"blockaudit-pepper"
        import hashlib
        return hashlib.sha256(pepper + p.encode("utf-8")).hexdigest()
    def _verify_password(p: str, ph: str) -> bool:
        import hmac
        return hmac.compare_digest(_hash_password(p), ph)
    if not user or not _verify_password(password, user["password_hash"]):
        return templates.TemplateResponse("fa_login.html", {"request": request, "error": "Credenciales inválidas"})
    request.session["user"] = {"username": user["username"], "role": user["role"]}
    dest = "/ui/admin" if user["role"] == "admin" else "/ui/operative"
    return RedirectResponse(url=dest, status_code=302)

@app.get("/ui/register")
def ui_register(request: Request):
    return templates.TemplateResponse("fa_register.html", {"request": request, "error": None})

@app.post("/ui/register")
def ui_register_post(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("user")):
    def _hash_password(p: str) -> str:
        pepper = b"blockaudit-pepper"
        import hashlib
        return hashlib.sha256(pepper + p.encode("utf-8")).hexdigest()
    if role not in ("user", "admin"):
        role = "user"
    if get_user(username):
        return templates.TemplateResponse("fa_register.html", {"request": request, "error": "Usuario ya existe"})
    ok = create_user(username, _hash_password(password), role)
    if not ok:
        return templates.TemplateResponse("fa_register.html", {"request": request, "error": "No se pudo crear el usuario"})
    request.session["user"] = {"username": username, "role": role}
    dest = "/ui/admin" if role == "admin" else "/ui/operative"
    return RedirectResponse(url=dest, status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/ui")


# --- API: crear evento en blockchain ---
class EventIn(BaseModel):
    entidad: str = Field(
        min_length=1,
        max_length=64,
        description="Identificador de entidad. Patrón permitido: [A-Za-z0-9_.:-]",
    )
    evento: str = Field(
        description=f"Tipo de evento. Valores permitidos: {', '.join(EVENTOS_TIPICOS)}",
    )
    fecha: str | None = Field(
        default=None,
        description="Fecha ISO. Acepta YYYY-MM-DD[,THH:MM[:SS]] y se normaliza a YYYY-MM-DDTHH:MM:SSZ. Si se omite, se usa la hora actual.",
    )
    detalles: str | None = Field(
        default=None,
        max_length=1000,
        description="Detalles opcionales del evento (0-1000 caracteres). No colocar secretos.",
    )

    @field_validator("entidad")
    @classmethod
    def _val_entidad(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", v):
            raise ValueError("entidad contiene caracteres no permitidos (usa letras, números, _ . : -)")
        return v

    @field_validator("evento")
    @classmethod
    def _val_evento(cls, v: str) -> str:
        if v not in EVENTOS_TIPICOS:
            raise ValueError(f"evento no permitido. Valores válidos: {', '.join(EVENTOS_TIPICOS)}")
        return v

    @field_validator("fecha")
    @classmethod
    def _val_fecha(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        norm = _norm_iso(str(v))
        # Debe ser exactamente YYYY-MM-DDTHH:MM:SSZ
        try:
            datetime.strptime(norm, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            raise ValueError("fecha inválida. Usa YYYY-MM-DD[THH:MM[:SS]] o deja vacío.")
        return norm


class EventOut(BaseModel):
    ok: bool
    tx_hash: str
    hash: str
    timestamp: str
    nonce: str
    evento: Dict[str, Any]


class VerifyResponse(BaseModel):
    ok: bool
    tx_hash: Optional[str] = None
    message: Optional[str] = None
    expected_digest: Optional[str] = None
    onchain_digest: Optional[str] = None
    equality: Optional[bool] = None
    diffs: Optional[Dict[str, Any]] = None
    expected_json: Optional[Dict[str, Any]] = None
    onchain_json: Optional[Dict[str, Any]] = None


@app.post(
    "/api/events",
    response_model=EventOut,
    summary="Crear evento y anclar en blockchain",
    description=(
        "Crea un evento (entidad, evento, fecha, detalles), genera hash dinámico, "
        "lo envía a Ganache y persiste en SQLite. La fecha se normaliza a ISO si se provee."
    ),
    responses={
        400: {
            "description": "Validación fallida del payload",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_event": {
                            "summary": "Evento no permitido",
                            "value": {"detail": "evento no permitido. Valores válidos: LOGIN_SUCCESS, LOGIN_FAIL, ACCESS_RESOURCE, LOGOUT, ERROR_INTERNAL, CONFIG_CHANGE"},
                        },
                        "invalid_entidad": {
                            "summary": "Entidad con caracteres no permitidos",
                            "value": {"detail": "entidad contiene caracteres no permitidos (usa letras, números, _ . : -)"},
                        },
                        "invalid_fecha": {
                            "summary": "Fecha inválida",
                            "value": {"detail": "fecha inválida. Usa YYYY-MM-DD[THH:MM[:SS]] o deja vacío."},
                        },
                    }
                }
            },
        },
        503: {
            "description": "Blockchain (Ganache) no conectada",
            "content": {
                "application/json": {
                    "example": {"detail": "Blockchain no conectada (Ganache)."}
                }
            },
        },
        500: {
            "description": "Error interno creando el evento",
            "content": {
                "application/json": {
                    "example": {"detail": "Error creando evento: <detalle>"}
                }
            },
        },
    },
)
def api_create_event(
    payload: EventIn = Body(
        ...,
        example={
            "entidad": "user_alice",
            "evento": "ACCESS_RESOURCE",
            "fecha": "2025-11-18T16:45:30",
            "detalles": "resource /api/demo"
        },
    )
):
    try:
        fecha = (payload.fecha or ahora_iso())
        # Construir evento dict coherente con construir_log
        evento_dict = {
            "entidad": payload.entidad,
            "evento": payload.evento,
            "fecha": fecha,
            "detalles": payload.detalles,
        }
        # Hash dinámico y log
        hash_result, timestamp, nonce = generar_hash_dinamico(payload.entidad)
        log = construir_log(evento_dict, hash_result, timestamp)

        # Enviar a blockchain
        blockchain = BlockchainClient()
        if not blockchain.conectado():
            raise HTTPException(status_code=503, detail="Blockchain no conectada (Ganache).")
        tx_hash = enviar_evento_a_blockchain(blockchain, log)

        # Persistir en BDs
        insertar_log_operativo(
            OPERATIVE_DB_PATH,
            hash_result,
            payload.evento,
            fecha,
            tx_hash,
            payload.detalles,
        )
        insertar_mapeo_hash(
            ADMIN_DB_PATH,
            hash_result,
            payload.entidad,
            timestamp,
            nonce,
            payload.evento,
            payload.detalles,
        )

        return {
            "ok": True,
            "tx_hash": tx_hash,
            "hash": hash_result,
            "timestamp": timestamp,
            "nonce": nonce,
            "evento": evento_dict,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creando evento: {e}")


@app.get(
    "/api/verify",
    response_model=VerifyResponse,
    summary="Verificar integridad on-chain",
    description=(
        "Verifica que el JSON guardado en blockchain para una transacción coincide con los datos locales. "
        "Proveer 'tx' (hash de transacción 0x...) o 'hash' (hash_entidad); si se provee 'hash', se verifica el último log asociado."
    ),
)
def api_verify(
    tx: str | None = Query(None, description="Hash de transacción (0x...)"),
    hash: str | None = Query(None, description="Hash de entidad local (hash_entidad)"),
):
    if not tx and not hash:
        raise HTTPException(status_code=400, detail="Debe proporcionar 'tx' o 'hash'.")

    # Buscar fila operativa a partir de tx o hash
    if tx:
        op_row = obtener_log_por_tx(OPERATIVE_DB_PATH, tx)
        if not op_row:
            raise HTTPException(status_code=404, detail="No se encontró el registro operativo para el tx_hash proporcionado.")
    else:
        op_row = obtener_ultimo_log_por_hash(OPERATIVE_DB_PATH, hash)  # type: ignore[arg-type]
        if not op_row:
            raise HTTPException(status_code=404, detail="No se encontró ningún registro operativo asociado a ese hash.")

    # Mapping admin para timestamp_hash
    import sqlite3
    from database.db_admin import inicializar_admin_db
    inicializar_admin_db(ADMIN_DB_PATH)
    con = sqlite3.connect(ADMIN_DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM admin_mappings WHERE hash = ? LIMIT 1", (op_row["hash_entidad"],))
    admin_row = cur.fetchone()
    con.close()
    admin_dict = {k: admin_row[k] for k in admin_row.keys()} if admin_row else None

    expected = build_expected_log(op_row, admin_dict)
    tx_hash = op_row["tx_hash"]
    result = verify_tx_matches_expected(tx_hash, expected)

    # Adaptar a VerifyResponse
    expected_digest = result.get("expected_digest")
    onchain_digest = result.get("onchain_digest")
    equality = None
    proofs = result.get("proofs") or {}
    if isinstance(proofs, dict) and "equality" in proofs:
        equality = proofs.get("equality")
    elif expected_digest and onchain_digest:
        equality = expected_digest == onchain_digest

    out: Dict[str, Any] = {
        "ok": bool(result.get("ok")),
        "tx_hash": result.get("tx_hash"),
        "message": result.get("message") or result.get("reason"),
        "expected_digest": expected_digest,
        "onchain_digest": onchain_digest,
        "equality": equality,
        "diffs": result.get("diffs"),
        "expected_json": result.get("expected_json"),
        "onchain_json": result.get("onchain_json"),
    }
    return out

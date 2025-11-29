# BlockAudit

Sistema de registros inmutables con anclaje en blockchain (Ganache) y persistencia local en SQLite. Incluye:
- Flujo principal (`main.py`) que genera eventos simulados, produce hash dinámico y guarda transacción en la cadena.
- Dos bases de datos: operativa (registro de eventos y tx_hash) y administrativa (mapeo hash -> entidad + metadatos).
- Interfaces web: UI con Flask y UI/API con FastAPI.

## Arquitectura
```
core/            # Generación de eventos, hashing y construcción del log
blockchain/      # Cliente Web3 y gestor de transacciones
database/        # Acceso y migración de esquemas SQLite
utils/           # Configuración y timestamps
web/             # Flask (flask_app.py) + FastAPI (fastapi_app.py) + plantillas
main.py          # Orquestación del flujo
```

### Tablas SQLite
Operativa (`operative_logs`):
- id
- hash_entidad
- evento
- fecha
- tx_hash
- detalles

Administrativa (`admin_mappings`):
- id
- hash (UNIQUE)
- entidad_real
- timestamp
- nonce
- evento
- detalles

Migraciones ligeras se realizan automáticamente al inicializar cada DB (se añaden columnas si faltan).

## Requisitos
- Python 3.9+
- Ganache (CLI `npx ganache` o aplicación) escuchando en `http://127.0.0.1:8545` (configurable vía `GANACHE_URL`).

## Guía rápida (Windows PowerShell)
```pwsh
# 1) Crear y activar entorno virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) Instalar dependencias
pip install -r requirements.txt

# 3) Arrancar Ganache en 127.0.0.1:8545 (como lo usamos aquí)
npx ganache --port 8545 --host 127.0.0.1
# (déjalo corriendo; en otra terminal continúa con el paso 4)

# 4) Lanzar la UI/API FastAPI (tal como lo invocaste)
Push-Location "c:\Users\Public\Dise\Proyecto_Critp"; .\.venv\Scripts\Activate.ps1; `
python -m uvicorn web.fastapi_app:app --host 127.0.0.1 --port 8000

# 5) Abrir
# UI:   http://127.0.0.1:8000/ui
# Docs: http://127.0.0.1:8000/docs

# 6) (Opcional) Disparar un evento manual inmediato
python .\main.py
# o bien
python -c "from main import procesar_evento; print(procesar_evento())"
```

## Instalación
```pwsh
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Ejecución del flujo principal
```pwsh
# Arrancar Ganache en segundo plano (opcional como job)
Start-Job -Name Ganache -ScriptBlock { npx ganache -p 8545 -h 127.0.0.1 }
$env:GANACHE_URL = "http://127.0.0.1:8545"
python .\main.py
```
Genera un evento, envía transacción con datos embebidos y persiste en ambas tablas.

## UI Flask
```pwsh
flask --app web.flask_app run --port 5000
# Navegar a http://127.0.0.1:5000
```
Rutas:
- `/operative` (filtros: evento, hash, fecha; muestra detalles)
- `/admin` (filtros: evento, hash, fecha; muestra evento y detalles)

## FastAPI (UI + API)
```pwsh
python -m uvicorn web.fastapi_app:app --host 127.0.0.1 --port 8000
# UI: http://127.0.0.1:8000/ui
# Swagger: http://127.0.0.1:8000/docs
```
Endpoints clave:
- `GET /api/operative` (limit, offset, filtros vía /ui)
- `GET /api/admin`
- `GET /api/admin/{hash}` (resolver entidad real)
- `POST /api/events` (crear evento on-chain y persistir en SQLite)

- `GET /api/verify` (verificar integridad on-chain)
	- Query: `tx` (hash de transacción 0x...) o `hash` (hash_entidad)
	- Respuesta: `ok`, `tx_hash`, `expected_digest`, `onchain_digest`, `equality`, `diffs`, `expected_json`, `onchain_json`

Ejemplo (PowerShell):
```pwsh
$body = @{ entidad = "user_alice"; evento = "ACCESS_RESOURCE"; fecha = "2025-11-18T16:45:30"; detalles = "resource /api/demo" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/events" -Method Post -Body $body -ContentType 'application/json'
```

Verificación por API:
```pwsh
# Por tx hash
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/verify?tx=0xABC..." -Method Get

# Por hash_entidad (usa el último registro operativo asociado)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/verify?hash=9e6fde9e..." -Method Get
```

## Autenticación básica (UI)
- Registro e inicio de sesión: `/ui/register`, `/ui/login`, `/logout`.
- Roles:
	- `admin`: acceso a `/ui/admin` y `/ui/operative`.
	- `user`: acceso solo a `/ui/operative`.
- Sesiones: se almacenan en cookie (SessionMiddleware). Cambia `SESSION_SECRET` vía env.

Admin por defecto (opcional):
```pwsh
$env:ADMIN_DEFAULT_USER = "admin"
$env:ADMIN_DEFAULT_PASS = "admin"
python -m uvicorn web.fastapi_app:app --host 127.0.0.1 --port 8000
```
Si el usuario no existe, se crea automáticamente con rol `admin`.

Notas:
- Hash de contraseña simple (SHA-256 con pepper) para demo; en producción usa bcrypt/argon2.
- Las vistas UI redirigen a login si no hay sesión; `/ui/admin` devuelve 403 si el rol no es `admin`.

### POST /api/events

- Método: `POST`
- Ruta: `http://127.0.0.1:8000/api/events`
- Content-Type: `application/json`

Body (JSON):
- entidad: cadena (1-64); permitido `[A-Za-z0-9_.:-]`
- evento: uno de `[LOGIN_SUCCESS, LOGIN_FAIL, ACCESS_RESOURCE, LOGOUT, ERROR_INTERNAL, CONFIG_CHANGE]`
- fecha: opcional; acepta `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM` o `YYYY-MM-DDTHH:MM:SS`; se normaliza a `YYYY-MM-DDTHH:MM:SSZ`; si no se envía, se usa la hora actual.
- detalles: opcional, cadena hasta 1000 chars.

Ejemplo (curl):
```bash
curl -X POST http://127.0.0.1:8000/api/events \
	-H "Content-Type: application/json" \
	-d '{
		"entidad": "user_alice",
		"evento": "ACCESS_RESOURCE",
		"fecha": "2025-11-18T16:45:30",
		"detalles": "resource /api/demo"
	}'
```

Respuesta (200):
```json
{
	"ok": true,
	"tx_hash": "0x...",
	"hash": "9e6fde9e...",
	"timestamp": "2025-11-18T16:45:30Z",
	"nonce": "12345",
	"evento": {
		"entidad": "user_alice",
		"evento": "ACCESS_RESOURCE",
		"fecha": "2025-11-18T16:45:30Z",
		"detalles": "resource /api/demo"
	}
}
```

Errores:
- 400: validación fallida (caracteres no permitidos en `entidad`, `evento` no válido, `fecha` inválida)
- 503: blockchain no conectada (Ganache)
- 500: error interno creando el evento

## Filtros
Los filtros aplican búsquedas sobre columnas y admiten rango de fechas:
- Evento: `evento LIKE %valor%`
- Hash: `hash_entidad` (operativa) / `hash` (administrativa)
- Fecha exacta/parcial: `fecha LIKE %YYYY-MM-DD%` o `timestamp LIKE %YYYY-MM-DD%`
- Rango: parámetros `fecha_desde` y/o `fecha_hasta` (ISO `YYYY-MM-DD`)

Ejemplos (UI):
- Operativa: `?evento=LOGIN&fecha_desde=2025-11-01&fecha_hasta=2025-11-30`
- Admin: `?hash=abc&fecha=2025-11-18`

## Automatización de eventos
Al iniciar FastAPI se levanta un scheduler en segundo plano que genera un
evento automáticamente cada 5 minutos y lo envía a blockchain. Requiere Ganache activo.
Puedes ajustar el intervalo editando `EVENT_INTERVAL_SECONDS` en `web/fastapi_app.py`.

## Esquemas y Migraciones
Si las columnas nuevas (`detalles`, `evento`) no existían en versiones anteriores, se añaden vía `ALTER TABLE` al iniciar. No se eliminan datos previos.

## Errores Comunes
| Situación | Causa | Solución |
|-----------|-------|----------|
| `Blockchain client no conectado` | Ganache apagado o puerto distinto | Arrancar Ganache y verificar `GANACHE_URL` |
| `jinja2.exceptions.UndefinedError: 'max' is undefined` | Uso de `max()` en plantillas | Reemplazado por cálculo en Python (`prev_offset`, `next_offset`) |
| Filtro sin resultados | Criterio demasiado restrictivo | Probar sin fecha o con parte del evento |
| ImportError `web3` en editor | Intérprete incorrecto | Seleccionar venv en VS Code (`.venv`) |

## Desarrollo y Extensión
- Añadir export JSON/CSV desde UI.
- Agregar rango de fechas (date-from/date-to) usando entre comparaciones.
- Indexar columnas críticas para búsquedas (SQLite: crear índices en tablas si crecieran demasiado).

## Limpieza / Reset
Para reiniciar bases:
```pwsh
Remove-Item .\data\blockaudit_admin.db, .\data\blockaudit_operational.db
python .\main.py   # Se recrean
```

## Parar Ganache Job
```pwsh
Stop-Job -Name Ganache; Remove-Job -Name Ganache
```

## Seguridad
La transacción escribe el log completo en campo `data`. No colocar secretos en `detalles`. Para producción: cifrar antes de enviar o almacenar referenciado.

## Licencia
(Sin encabezado de licencia; añadir si es necesario.)

## Troubleshooting Rápido
1. Verifica Ganache: `curl http://127.0.0.1:8545` debe responder JSON RPC.
2. Comprueba versión web3: `python -c "import web3; print(web3.__version__)"`.
3. Revisa que `data/` tenga ambas bases tras ejecutar `main.py`.
4. Si filtros no funcionan, imprime manualmente: `python -c "from database.db_operational import listar_logs_operativos; from utils.config import OPERATIVE_DB_PATH; print(listar_logs_operativos(OPERATIVE_DB_PATH, limit=5))"`.

---
Cualquier mejora adicional (rango de fechas, autenticación, exportaciones) se puede incorporar de forma modular.

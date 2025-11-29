import time, random
from utils.timestamp import ahora_iso

EVENTOS_TIPICOS = [
    "LOGIN_SUCCESS",
    "LOGIN_FAIL",
    "ACCESS_RESOURCE",
    "LOGOUT",
    "ERROR_INTERNAL",
    "CONFIG_CHANGE"
]

ENTIDADES_EJEMPLO = [
    "user_alice",
    "user_bob",
    "server_web_01",
    "server_ldap_01",
    "service_auth"
]

def generar_evento() -> dict:
    """
    Genera un evento simulado con campos básicos:
    entidad, evento, fecha, detalles (opcional)
    """
    entidad = random.choice(ENTIDADES_EJEMPLO)
    evento = random.choice(EVENTOS_TIPICOS)
    fecha = ahora_iso()
    detalles = None

   
    if evento == "LOGIN_FAIL":
        detalles = f"failed login from 10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    elif evento == "LOGIN_SUCCESS":
        detalles = f"login ok from 10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    elif evento == "ACCESS_RESOURCE":
        detalles = f"resource /api/data/{random.randint(1,100)} accessed"
    elif evento == "ERROR_INTERNAL":
        detalles = f"exception code {random.randint(1000,9999)}"
    elif evento == "CONFIG_CHANGE":
        detalles = f"param updated: max_conn -> {random.randint(10,500)}"

    return {
        "entidad": entidad,
        "evento": evento,
        "fecha": fecha,
        "detalles": detalles
    }

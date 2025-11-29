
from typing import Dict

def construir_log(evento: Dict, hash_entidad: str, timestamp: str) -> Dict:
    """
    Construye la estructura del log que se enviará a blockchain.
    """
    log = {
        "hash_entidad": hash_entidad,
        "evento": evento.get("evento"),
        "fecha_evento": evento.get("fecha"),
        "timestamp_hash": timestamp,
        "detalles": evento.get("detalles")
    }
    return log

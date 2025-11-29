
import hashlib, time, random
from typing import Tuple

def generar_hash_dinamico(entidad: str) -> Tuple[str, str, str]:
    """
    Genera un hash SHA256 dinámico basado en:
    entidad + timestamp_unix + nonce
    Retorna (hash_hex, timestamp_iso, nonce)
    """
    
    timestamp_epoch = str(int(time.time()))
    nonce = str(random.randint(100000, 999999))
    texto = f"{entidad}-{timestamp_epoch}-{nonce}"
    h = hashlib.sha256(texto.encode('utf-8')).hexdigest()
  
    timestamp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(timestamp_epoch)))
    return h, timestamp_iso, nonce

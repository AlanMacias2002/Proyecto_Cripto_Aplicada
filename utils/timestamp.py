import time

def ahora_iso() -> str:
    """
    Retorna timestamp ISO UTC simple, por ejemplo: 2025-11-17T21:00:00Z
    """
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
